"""
JACS Simplified API

A streamlined interface for the most common JACS operations:
- create(): Create a new agent with keys
- load(): Load an existing agent from config
- verify_self(): Verify the loaded agent's integrity
- update_agent(): Update the agent document with new data
- update_document(): Update an existing document with new data
- sign_message(): Sign a text message
- sign_file(): Sign a file with optional embedding
- verify(): Verify any signed document
- create_agreement(): Create a multi-party agreement
- sign_agreement(): Sign an existing agreement
- check_agreement(): Check agreement status

Example:
    import jacs.simple as jacs

    # Create or load an agent
    agent_info = jacs.load("./jacs.config.json")

    # Sign a message
    signed = jacs.sign_message("Hello, World!")
    print(signed.document_id)

    # Verify it
    result = jacs.verify(signed.raw_json)
    print(f"Valid: {result.valid}")

    # Create a multi-party agreement
    agreement = jacs.create_agreement(
        document={"proposal": "Merge codebase"},
        agent_ids=["agent-1", "agent-2"],
        question="Do you approve?"
    )

    # Check agreement status
    status = jacs.check_agreement(agreement)
    print(f"Complete: {status.complete}, Pending: {status.pending}")
"""

import json
import os
from pathlib import Path
from typing import Optional, Union, List, Any

# Import types
from .types import (
    AgentInfo,
    Attachment,
    SignedDocument,
    VerificationResult,
    SignerStatus,
    AgreementStatus,
    JacsError,
    ConfigError,
    AgentNotLoadedError,
    SigningError,
    VerificationError,
    TrustError,
)

# Import the Rust bindings
try:
    from . import JacsAgent
except ImportError:
    # Fallback for when running directly
    import jacs as _jacs_module
    JacsAgent = _jacs_module.JacsAgent

# Global agent instance for simplified API
_global_agent: Optional[JacsAgent] = None
_agent_info: Optional[AgentInfo] = None


def _get_agent() -> JacsAgent:
    """Get the global agent, raising an error if not loaded."""
    if _global_agent is None:
        raise AgentNotLoadedError(
            "No agent loaded. Call jacs.load() or jacs.create() first."
        )
    return _global_agent


def _parse_signed_document(json_str: str) -> SignedDocument:
    """Parse a JSON string into a SignedDocument."""
    try:
        data = json.loads(json_str)

        # Extract fields from JACS document structure
        doc_id = data.get("id", data.get("jacsId", ""))
        version = data.get("jacsVersion", data.get("version", ""))

        # Get signature info
        sig_info = data.get("jacsSignature", {})
        signature = sig_info.get("signature", "")
        signer_id = sig_info.get("agentId", sig_info.get("agentID", ""))
        signed_at = sig_info.get("date", "")

        # Get hash info
        hash_info = data.get("jacsHash", {})
        content_hash = hash_info.get("hash", "")

        # Get payload - could be jacsDocument or direct content
        payload = data.get("jacsDocument", data.get("payload", data))

        # Get attachments
        attachments = []
        files_data = data.get("jacsFiles", [])
        for f in files_data:
            attachments.append(Attachment(
                filename=f.get("filename", ""),
                mime_type=f.get("mimeType", "application/octet-stream"),
                content_hash=f.get("sha256", ""),
                content=f.get("content"),
                size_bytes=f.get("size", 0),
            ))

        return SignedDocument(
            document_id=doc_id,
            version=version,
            content_hash=content_hash,
            signature=signature,
            signer_id=signer_id,
            signed_at=signed_at,
            payload=payload,
            attachments=attachments,
            raw_json=json_str,
        )
    except json.JSONDecodeError as e:
        raise JacsError(f"Invalid JSON document: {e}")


def create(
    name: Optional[str] = None,
    agent_type: str = "service",
    algorithm: str = "RSA",
    config_path: Optional[str] = None,
) -> AgentInfo:
    """Create a new JACS agent with cryptographic keys.

    This is the simplest way to get started with JACS. It creates:
    - A new agent identity (UUID)
    - A cryptographic key pair
    - A configuration file
    - A signed agent document

    Args:
        name: Optional human-readable name for the agent
        agent_type: Type of agent ("service", "user", "system")
        algorithm: Cryptographic algorithm ("RSA", "ML-DSA", "DILITHIUM")
        config_path: Where to save the config (default: ./jacs.config.json)

    Returns:
        AgentInfo with the new agent's details

    Example:
        agent = jacs.create(name="My Agent")
        print(f"Created agent: {agent.agent_id}")
    """
    global _global_agent, _agent_info

    # Use default config path if not provided
    if config_path is None:
        config_path = "./jacs.config.json"

    try:
        # Import the CLI utilities for agent creation
        from . import handle_agent_create_py, handle_config_create_py

        # Create config file first
        handle_config_create_py()

        # Create the agent with keys
        handle_agent_create_py(None, True)

        # Now load the created agent
        return load(config_path)

    except ImportError:
        # If the CLI utilities aren't available, create manually
        raise JacsError(
            "Agent creation requires the full JACS package. "
            "Please use the CLI: jacs create"
        )


def load(config_path: Optional[str] = None) -> AgentInfo:
    """Load an existing JACS agent from configuration.

    Args:
        config_path: Path to jacs.config.json (default: ./jacs.config.json)

    Returns:
        AgentInfo with the loaded agent's details

    Raises:
        ConfigError: If config file not found or invalid
        JacsError: If agent loading fails

    Example:
        agent = jacs.load("./jacs.config.json")
        print(f"Loaded: {agent.name}")
    """
    global _global_agent, _agent_info

    # Use default config path if not provided
    if config_path is None:
        config_path = "./jacs.config.json"

    # Check if config exists
    if not os.path.exists(config_path):
        raise ConfigError(
            f"Config file not found: {config_path}\n"
            "Run 'jacs create' or call jacs.create() to create a new agent."
        )

    try:
        # Create a new JacsAgent instance
        _global_agent = JacsAgent()

        # Load the agent from config
        _global_agent.load(config_path)

        # Read config to get agent info
        with open(config_path, 'r') as f:
            config = json.load(f)

        # Extract agent ID from config
        agent_id_version = config.get("jacs_agent_id_and_version", "")
        parts = agent_id_version.split(":") if agent_id_version else ["", ""]
        agent_id = parts[0] if parts else ""
        version = parts[1] if len(parts) > 1 else ""

        key_dir = config.get("jacs_key_directory", "./jacs_keys")
        _agent_info = AgentInfo(
            agent_id=agent_id,
            version=version,
            name=config.get("name"),
            public_key_hash="",  # Will be populated after verification
            created_at="",
            algorithm=config.get("jacs_agent_key_algorithm", "RSA"),
            config_path=config_path,
            public_key_path=os.path.join(key_dir, "jacs.public.pem"),
        )

        return _agent_info

    except FileNotFoundError:
        raise ConfigError(f"Config file not found: {config_path}")
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid config file: {e}")
    except Exception as e:
        raise JacsError(f"Failed to load agent: {e}")


def verify_self() -> VerificationResult:
    """Verify the currently loaded agent's integrity.

    Checks both the cryptographic signature and content hash
    of the loaded agent document.

    Returns:
        VerificationResult indicating if the agent is valid

    Raises:
        AgentNotLoadedError: If no agent is loaded

    Example:
        result = jacs.verify_self()
        if result.valid:
            print("Agent integrity verified")
        else:
            print(f"Error: {result.error}")
    """
    agent = _get_agent()

    try:
        # verify_agent returns True on success, raises on failure
        agent.verify_agent(None)

        return VerificationResult(
            valid=True,
            signer_id=_agent_info.agent_id if _agent_info else "",
            signer_public_key_hash=_agent_info.public_key_hash if _agent_info else "",
            content_hash_valid=True,
            signature_valid=True,
        )
    except Exception as e:
        return VerificationResult(
            valid=False,
            errors=[str(e)],
        )


def update_agent(new_agent_data: Union[str, dict]) -> str:
    """Update the agent document with new data and re-sign it.

    This function expects a complete agent document (not partial updates).
    Use export_agent() to get the current document, modify it, then pass it here.
    The function will create a new version, re-sign, and re-hash the document.

    Args:
        new_agent_data: Complete agent document as JSON string or dict

    Returns:
        The updated and re-signed agent document as a JSON string

    Raises:
        AgentNotLoadedError: If no agent is loaded
        JacsError: If update fails

    Example:
        # Get current agent, modify, and update
        agent_doc = json.loads(jacs.export_agent())
        agent_doc["jacsAgentType"] = "updated-service"
        updated = jacs.update_agent(agent_doc)
        print("Agent updated with new version")
    """
    agent = _get_agent()

    # Convert dict to JSON string if needed
    if isinstance(new_agent_data, dict):
        data_string = json.dumps(new_agent_data)
    else:
        data_string = new_agent_data

    try:
        return agent.update_agent(data_string)
    except Exception as e:
        raise JacsError(f"Failed to update agent: {e}")


def update_document(
    document_id: str,
    new_document_data: Union[str, dict],
    attachments: Optional[List[str]] = None,
    embed: bool = False,
) -> SignedDocument:
    """Update an existing document with new data and re-sign it.

    Use sign_message() to create a document first, then use this to update it.
    The function will create a new version, re-sign, and re-hash the document.

    Args:
        document_id: The document ID (jacsId) to update
        new_document_data: The updated document as JSON string or dict
        attachments: Optional list of file paths to attach
        embed: If True, embed attachment contents

    Returns:
        SignedDocument with the updated document

    Raises:
        AgentNotLoadedError: If no agent is loaded
        JacsError: If update fails

    Example:
        # Create a document first
        signed = jacs.sign_message({"status": "pending"})

        # Later, update it
        doc = json.loads(signed.raw_json)
        doc["content"]["status"] = "approved"
        updated = jacs.update_document(signed.document_id, doc)
        print("Document updated with new version")
    """
    agent = _get_agent()

    # Convert dict to JSON string if needed
    if isinstance(new_document_data, dict):
        data_string = json.dumps(new_document_data)
    else:
        data_string = new_document_data

    try:
        result = agent.update_document(
            document_id,
            data_string,
            attachments,
            embed,
        )
        return _parse_signed_document(result)
    except Exception as e:
        raise JacsError(f"Failed to update document: {e}")


def create_agreement(
    document: Union[str, dict, SignedDocument],
    agent_ids: List[str],
    question: Optional[str] = None,
    context: Optional[str] = None,
    field_name: Optional[str] = None,
) -> SignedDocument:
    """Create a multi-party agreement requiring signatures from specified agents.

    This creates an agreement on a document that must be signed by all specified
    agents before it is considered complete. Use this for scenarios requiring
    multi-party approval, such as contract signing or governance decisions.

    Args:
        document: The document to create an agreement on (JSON string, dict, or SignedDocument)
        agent_ids: List of agent IDs required to sign the agreement
        question: Optional question or purpose of the agreement (e.g., "Do you approve this proposal?")
        context: Optional additional context for signers
        field_name: Optional custom field name for the agreement (default: "jacsAgreement")

    Returns:
        SignedDocument containing the agreement document

    Raises:
        AgentNotLoadedError: If no agent is loaded
        JacsError: If agreement creation fails

    Example:
        # Create an agreement requiring two approvers
        agreement = jacs.create_agreement(
            document={"proposal": "Merge codebases A and B"},
            agent_ids=["agent-1-uuid", "agent-2-uuid"],
            question="Do you approve this merge?",
            context="This will combine repositories A and B"
        )
        print(f"Agreement created: {agreement.document_id}")
        # Send to each agent for signing
    """
    agent = _get_agent()

    # Convert to JSON string if needed
    if isinstance(document, SignedDocument):
        doc_str = document.raw_json
    elif isinstance(document, dict):
        doc_str = json.dumps(document)
    else:
        doc_str = document

    try:
        result = agent.create_agreement(
            doc_str,
            agent_ids,
            question,
            context,
            field_name,
        )
        return _parse_signed_document(result)
    except Exception as e:
        raise JacsError(f"Failed to create agreement: {e}")


def sign_agreement(
    document: Union[str, dict, SignedDocument],
    field_name: Optional[str] = None,
) -> SignedDocument:
    """Sign an existing multi-party agreement as the current agent.

    When an agreement is created, each required signer must call this function
    to add their signature. The agreement is complete when all signers have signed.

    Args:
        document: The agreement document to sign (JSON string, dict, or SignedDocument)
        field_name: Optional custom field name for the agreement (default: "jacsAgreement")

    Returns:
        SignedDocument with this agent's signature added

    Raises:
        AgentNotLoadedError: If no agent is loaded
        JacsError: If signing fails (e.g., agent not in required signers list)

    Example:
        # Receive agreement from coordinator
        agreement_json = receive_agreement_from_coordinator()

        # Sign it
        signed = jacs.sign_agreement(agreement_json)

        # Send back to coordinator or pass to next signer
        send_to_coordinator(signed.raw_json)
    """
    agent = _get_agent()

    # Convert to JSON string if needed
    if isinstance(document, SignedDocument):
        doc_str = document.raw_json
    elif isinstance(document, dict):
        doc_str = json.dumps(document)
    else:
        doc_str = document

    try:
        result = agent.sign_agreement(doc_str, field_name)
        return _parse_signed_document(result)
    except Exception as e:
        raise JacsError(f"Failed to sign agreement: {e}")


def check_agreement(
    document: Union[str, dict, SignedDocument],
    field_name: Optional[str] = None,
) -> AgreementStatus:
    """Check the status of a multi-party agreement.

    Use this to determine which agents have signed and whether the agreement
    is complete (all required signatures collected).

    Args:
        document: The agreement document to check (JSON string, dict, or SignedDocument)
        field_name: Optional custom field name for the agreement (default: "jacsAgreement")

    Returns:
        AgreementStatus with completion status and signer details

    Raises:
        AgentNotLoadedError: If no agent is loaded
        JacsError: If checking fails (e.g., document has no agreement field)

    Example:
        status = jacs.check_agreement(agreement_doc)
        if status.complete:
            print("All parties have signed!")
            process_completed_agreement(agreement_doc)
        else:
            print(f"Waiting for signatures from: {status.pending}")
            for signer in status.signers:
                if signer.signed:
                    print(f"  {signer.agent_id}: signed at {signer.signed_at}")
                else:
                    print(f"  {signer.agent_id}: pending")
    """
    agent = _get_agent()

    # Convert to JSON string if needed
    if isinstance(document, SignedDocument):
        doc_str = document.raw_json
    elif isinstance(document, dict):
        doc_str = json.dumps(document)
    else:
        doc_str = document

    try:
        result_json = agent.check_agreement(doc_str, field_name)
        result_data = json.loads(result_json)

        # Parse signers
        signers = []
        for signer_data in result_data.get("signers", []):
            signers.append(SignerStatus.from_dict(signer_data))

        return AgreementStatus(
            complete=result_data.get("complete", False),
            signers=signers,
            pending=result_data.get("pending", []),
        )
    except json.JSONDecodeError as e:
        raise JacsError(f"Invalid agreement status response: {e}")
    except Exception as e:
        raise JacsError(f"Failed to check agreement: {e}")


def sign_message(data: Any) -> SignedDocument:
    """Sign arbitrary data as a JACS message.

    Creates a cryptographically signed JACS document containing
    the data. The signature proves the data came from this agent
    and hasn't been modified.

    Args:
        data: The data to sign (dict, list, str, or any JSON-serializable value)

    Returns:
        SignedDocument containing the signed data

    Raises:
        AgentNotLoadedError: If no agent is loaded
        SigningError: If signing fails

    Example:
        # Sign a dict
        signed = jacs.sign_message({"action": "approve", "amount": 100})

        # Sign a string
        signed = jacs.sign_message("Hello, World!")

        print(signed.document_id)
        print(signed.raw)  # Send this to verify
    """
    agent = _get_agent()

    try:
        # Create a document with the data as payload
        doc_json = json.dumps({
            "jacsDocument": {
                "type": "message",
                "content": data,
            }
        })

        # Sign using the agent's create_document method
        result = agent.create_document(
            document_string=doc_json,
            custom_schema=None,
            outputfilename=None,
            no_save=True,  # Don't save to disk
            attachments=None,
            embed=None,
        )

        return _parse_signed_document(result)

    except Exception as e:
        raise SigningError(f"Failed to sign message: {e}")


def sign_file(
    file_path: str,
    embed: bool = False,
    mime_type: Optional[str] = None,
) -> SignedDocument:
    """Sign a file with optional embedding.

    Creates a signed document that attests to the file's contents.
    The signature covers a hash of the file, proving the file
    hasn't been modified since signing.

    Args:
        file_path: Path to the file to sign
        embed: If True, embed the file content in the document
        mime_type: Override auto-detected MIME type

    Returns:
        SignedDocument with file attachment

    Raises:
        AgentNotLoadedError: If no agent is loaded
        SigningError: If signing fails
        FileNotFoundError: If file doesn't exist

    Example:
        signed = jacs.sign_file("contract.pdf", embed=True)
        print(f"Signed {signed.attachments[0].filename}")
    """
    agent = _get_agent()

    # Check file exists
    if not os.path.exists(file_path):
        raise JacsError(f"File not found: {file_path}")

    try:
        # Create a minimal document that references the file
        doc_json = json.dumps({
            "jacsDocument": {
                "type": "file",
                "filename": os.path.basename(file_path),
            }
        })

        # Sign with attachment
        result = agent.create_document(
            document_string=doc_json,
            custom_schema=None,
            outputfilename=None,
            no_save=True,
            attachments=file_path,
            embed=embed,
        )

        return _parse_signed_document(result)

    except Exception as e:
        raise SigningError(f"Failed to sign file: {e}")


def verify(document: Union[str, dict, SignedDocument]) -> VerificationResult:
    """Verify any signed JACS document.

    This is the universal verification function. It works with:
    - JSON strings
    - Dictionaries
    - SignedDocument objects

    Args:
        document: The signed document to verify

    Returns:
        VerificationResult with verification status

    Example:
        result = jacs.verify(signed_json)
        if result.valid:
            print(f"Signed by: {result.signer_id}")
        else:
            print(f"Invalid: {result.error}")
    """
    agent = _get_agent()

    # Convert to JSON string if needed
    if isinstance(document, SignedDocument):
        doc_str = document.raw_json
    elif isinstance(document, dict):
        doc_str = json.dumps(document)
    else:
        doc_str = document

    try:
        # Verify the document
        is_valid = agent.verify_document(doc_str)

        # Parse to get signer info
        doc_data = json.loads(doc_str)
        sig_info = doc_data.get("jacsSignature", {})

        return VerificationResult(
            valid=is_valid,
            signer_id=sig_info.get("agentId", sig_info.get("agentID", "")),
            signer_public_key_hash=sig_info.get("publicKeyHash", ""),
            content_hash_valid=True,
            signature_valid=True,
            timestamp=sig_info.get("date", ""),
        )

    except Exception as e:
        return VerificationResult(
            valid=False,
            errors=[str(e)],
        )


def get_public_key() -> str:
    """Get the loaded agent's public key in PEM format.

    Returns:
        The public key as a PEM-encoded string

    Raises:
        AgentNotLoadedError: If no agent is loaded

    Example:
        pem = jacs.get_public_key()
        print(pem)  # Share this with others for verification
    """
    # Note: This requires the Rust binding to expose get_public_key_pem
    # For now, we read it from the key file
    global _agent_info

    if _agent_info is None or _global_agent is None:
        raise AgentNotLoadedError("No agent loaded")

    # Try to read from default public key location
    try:
        # Read config to find key location
        config_paths = [
            "./jacs.config.json",
            os.path.expanduser("~/.jacs/config.json"),
        ]

        for config_path in config_paths:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)

                key_dir = config.get("jacs_key_directory", "./jacs_keys")
                pub_key_file = config.get("jacs_agent_public_key_filename", "")

                if pub_key_file:
                    pub_key_path = os.path.join(key_dir, pub_key_file)
                    if os.path.exists(pub_key_path):
                        with open(pub_key_path, 'r') as f:
                            return f.read()

        raise JacsError("Could not find public key file")

    except Exception as e:
        raise JacsError(f"Failed to read public key: {e}")


def export_agent() -> str:
    """Export the agent document for sharing.

    Returns the complete agent JSON document that can be shared
    with other parties for trust establishment.

    Returns:
        The agent JSON document as a string

    Raises:
        AgentNotLoadedError: If no agent is loaded

    Example:
        agent_json = jacs.export_agent()
        # Send to another party for them to call trust_agent()
    """
    global _agent_info

    if _agent_info is None or _global_agent is None:
        raise AgentNotLoadedError("No agent loaded")

    try:
        # Read the agent file
        config_paths = [
            "./jacs.config.json",
            os.path.expanduser("~/.jacs/config.json"),
        ]

        for config_path in config_paths:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)

                data_dir = config.get("jacs_data_directory", "./jacs_data")
                agent_id = config.get("jacs_agent_id_and_version", "")

                agent_path = os.path.join(data_dir, "agent", f"{agent_id}.json")
                if os.path.exists(agent_path):
                    with open(agent_path, 'r') as f:
                        return f.read()

        raise JacsError("Could not find agent file")

    except Exception as e:
        raise JacsError(f"Failed to export agent: {e}")


def get_agent_info() -> Optional[AgentInfo]:
    """Get information about the currently loaded agent.

    Returns:
        AgentInfo if an agent is loaded, None otherwise
    """
    return _agent_info


def is_loaded() -> bool:
    """Check if an agent is currently loaded.

    Returns:
        True if an agent is loaded, False otherwise
    """
    return _global_agent is not None


__all__ = [
    # Core operations
    "create",
    "load",
    "verify_self",
    "update_agent",
    "update_document",
    "sign_message",
    "sign_file",
    "verify",
    # Agreement functions
    "create_agreement",
    "sign_agreement",
    "check_agreement",
    # Utility functions
    "get_public_key",
    "export_agent",
    "get_agent_info",
    "is_loaded",
    # Types (re-exported for convenience)
    "AgentInfo",
    "Attachment",
    "SignedDocument",
    "VerificationResult",
    "SignerStatus",
    "AgreementStatus",
    # Errors
    "JacsError",
    "ConfigError",
    "AgentNotLoadedError",
    "SigningError",
    "VerificationError",
    "TrustError",
]
