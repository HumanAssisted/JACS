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
- trust_agent(): Add an agent to the local trust store
- list_trusted_agents(): List all trusted agent IDs
- untrust_agent(): Remove an agent from the trust store
- is_trusted(): Check if an agent is trusted
- get_trusted_agent(): Get a trusted agent's JSON
- audit(): Run a read-only security audit and health checks

Environment Variables:
    JACS_KEY_RESOLUTION: Comma-separated order of key resolution when
                         verifying signatures (e.g. "local,dns").
                         Sources: local (trust store), dns (DNS TXT).
                         Default is "local".

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
import logging
import os
from pathlib import Path
from typing import Optional, Union, List, Any

# Configure module logger
logger = logging.getLogger("jacs")

# Import types
from .types import (
    AgentInfo,
    Attachment,
    SignedDocument,
    VerificationResult,
    SignerStatus,
    AgreementStatus,
    PublicKeyInfo,
    JacsError,
    ConfigError,
    AgentNotLoadedError,
    SigningError,
    VerificationError,
    TrustError,
    KeyNotFoundError,
    NetworkError,
)

# Import the Rust bindings
try:
    from . import JacsAgent
    from .jacs import trust_agent as _trust_agent
    from .jacs import list_trusted_agents as _list_trusted_agents
    from .jacs import untrust_agent as _untrust_agent
    from .jacs import is_trusted as _is_trusted
    from .jacs import get_trusted_agent as _get_trusted_agent
    from .jacs import verify_document_standalone as _verify_document_standalone
    from .jacs import verify_agent_dns as _verify_agent_dns
    from .jacs import audit as _audit
except ImportError:
    # Fallback for when running directly
    import jacs as _jacs_module
    JacsAgent = _jacs_module.JacsAgent
    _verify_document_standalone = _jacs_module.verify_document_standalone
    _verify_agent_dns = _jacs_module.verify_agent_dns
    _trust_agent = _jacs_module.trust_agent
    _list_trusted_agents = _jacs_module.list_trusted_agents
    _untrust_agent = _jacs_module.untrust_agent
    _is_trusted = _jacs_module.is_trusted
    _get_trusted_agent = _jacs_module.get_trusted_agent
    _audit = _jacs_module.audit

# Global agent instance for simplified API
_global_agent: Optional[JacsAgent] = None
_agent_info: Optional[AgentInfo] = None
_strict: bool = False


def _resolve_strict(explicit: Optional[bool]) -> bool:
    """Resolve strict mode: explicit param > JACS_STRICT_MODE env var > False."""
    if explicit is not None:
        return explicit
    return os.environ.get("JACS_STRICT_MODE", "").lower() in ("true", "1")


def is_strict() -> bool:
    """Returns whether the current agent is in strict mode."""
    return _strict


def reset():
    """Clear global agent state. Useful for test isolation.

    After calling reset(), you must call load() or create() again before
    using any signing or verification functions.
    """
    global _global_agent, _agent_info, _strict
    _global_agent = None
    _agent_info = None
    _strict = False




def _get_agent() -> JacsAgent:
    """Get the global agent, raising an error if not loaded."""
    if _global_agent is None:
        raise AgentNotLoadedError(
            "No agent loaded. Call jacs.quickstart() for zero-config setup, or jacs.load('path/to/config.json') for a persistent agent."
        )
    return _global_agent


def _resolve_config_relative_path(config_path: str, candidate: str) -> str:
    if os.path.isabs(candidate):
        return candidate
    return os.path.abspath(os.path.join(os.path.dirname(config_path), candidate))


def _read_document_by_id(document_id: str) -> Optional[dict]:
    """Best-effort read of a stored document for metadata extraction."""
    if _agent_info is None or not _agent_info.config_path:
        return None

    try:
        config_path = os.path.abspath(_agent_info.config_path)
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        data_dir = _resolve_config_relative_path(
            config_path, config.get("jacs_data_directory", "./jacs_data")
        )
        doc_path = os.path.join(data_dir, "documents", f"{document_id}.json")
        if not os.path.exists(doc_path):
            return None
        with open(doc_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _extract_signature_metadata(doc_data: Optional[dict]) -> tuple[str, str, str]:
    sig_info = doc_data.get("jacsSignature", {}) if isinstance(doc_data, dict) else {}
    return (
        sig_info.get("agentId", sig_info.get("agentID", "")),
        sig_info.get("publicKeyHash", ""),
        sig_info.get("date", ""),
    )


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
                filename=f.get("filename", f.get("path", "")),
                mime_type=f.get("mimeType", f.get("mimetype", "application/octet-stream")),
                content_hash=f.get("sha256", ""),
                content=f.get("content", f.get("contents")),
                size_bytes=f.get("size", f.get("sizeBytes", 0)),
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
    name: str = "jacs-agent",
    password: Optional[str] = None,
    algorithm: str = "pq2025",
    data_directory: str = "./jacs_data",
    key_directory: str = "./jacs_keys",
    config_path: str = "./jacs.config.json",
    agent_type: str = "ai",
    description: str = "",
    domain: Optional[str] = None,
    default_storage: str = "fs",
    strict: Optional[bool] = None,
) -> AgentInfo:
    """Create a new JACS agent with cryptographic keys (programmatic).

    This is the simplest way to get started with JACS. It creates:
    - A new agent identity (UUID)
    - A cryptographic key pair
    - A configuration file
    - A signed agent document

    Args:
        name: Human-readable name for the agent
        password: Password for encrypting the private key.
                  If not provided, falls back to JACS_PRIVATE_KEY_PASSWORD env var.
        algorithm: Signing algorithm ("pq2025", "ring-Ed25519", "RSA-PSS").
        data_directory: Directory for data storage (default: "./jacs_data")
        key_directory: Directory for keys (default: "./jacs_keys")
        config_path: Where to save the config (default: "./jacs.config.json")
        agent_type: Type of agent ("ai", "human", "hybrid")
        description: Optional description of the agent's purpose
        domain: Optional domain for DNSSEC fingerprint
        default_storage: Storage backend ("fs")

    Returns:
        AgentInfo with the new agent's details

    Raises:
        JacsError: If password is missing or agent creation fails

    Example:
        agent = jacs.create(
            name="My Agent",
            password="MyStr0ng!Pass#2024",
            algorithm="pq2025",
        )
        print(f"Created agent: {agent.agent_id}")
    """
    global _global_agent, _agent_info, _strict

    _strict = _resolve_strict(strict)

    # Resolve password
    resolved_password = password or os.environ.get("JACS_PRIVATE_KEY_PASSWORD", "")
    if not resolved_password:
        raise ConfigError(
            "Password is required for agent creation. "
            "Either pass it as the 'password' argument or set the "
            "JACS_PRIVATE_KEY_PASSWORD environment variable."
        )

    try:
        # Try using SimpleAgent.create_agent (programmatic, non-interactive)
        from . import SimpleAgent as _SimpleAgent

        agent_instance, info_dict = _SimpleAgent.create_agent(
            name=name,
            password=resolved_password,
            algorithm=algorithm,
            data_directory=data_directory,
            key_directory=key_directory,
            config_path=config_path,
            agent_type=agent_type,
            description=description,
            domain=domain or "",
            default_storage=default_storage,
        )

        # Load using the caller-provided password even when env var is unset.
        previous_password = os.environ.get("JACS_PRIVATE_KEY_PASSWORD")
        os.environ["JACS_PRIVATE_KEY_PASSWORD"] = resolved_password
        try:
            _global_agent = JacsAgent()
            _global_agent.load(config_path)
        finally:
            if previous_password is None:
                os.environ.pop("JACS_PRIVATE_KEY_PASSWORD", None)
            else:
                os.environ["JACS_PRIVATE_KEY_PASSWORD"] = previous_password

        _agent_info = AgentInfo(
            agent_id=info_dict.get("agent_id", ""),
            version=info_dict.get("version", ""),
            name=info_dict.get("name", name),
            public_key_hash="",
            created_at="",
            algorithm=info_dict.get("algorithm", algorithm),
            config_path=config_path,
            public_key_path=info_dict.get("public_key_path", ""),
        )

        logger.info("Agent created: id=%s, name=%s", _agent_info.agent_id, name)
        return _agent_info

    except ImportError:
        raise JacsError(
            "Agent creation requires the full JACS package. "
            "Please use the CLI: jacs init"
        )
    except Exception as e:
        raise JacsError(f"Failed to create agent: {e}")


def load(config_path: Optional[str] = None, strict: Optional[bool] = None) -> AgentInfo:
    """Load an existing JACS agent from configuration.

    Args:
        config_path: Path to jacs.config.json (default: ./jacs.config.json)
        strict: Enable strict mode. When True, verification failures raise
                exceptions instead of returning VerificationResult(valid=False).
                If None, falls back to JACS_STRICT_MODE env var, then False.

    Returns:
        AgentInfo with the loaded agent's details

    Raises:
        ConfigError: If config file not found or invalid
        JacsError: If agent loading fails

    Example:
        agent = jacs.load("./jacs.config.json", strict=True)
        print(f"Loaded: {agent.name}")
    """
    global _global_agent, _agent_info, _strict

    _strict = _resolve_strict(strict)

    # Use default config path if not provided
    if config_path is None:
        config_path = "./jacs.config.json"

    logger.debug("load() called with config_path=%s", config_path)

    # Check if config exists
    if not os.path.exists(config_path):
        logger.error("Config file not found: %s", config_path)
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

        logger.info("Agent loaded: id=%s, name=%s", agent_id, config.get("name"))
        return _agent_info

    except FileNotFoundError:
        logger.error("Config file not found: %s", config_path)
        raise ConfigError(f"Config file not found: {config_path}")
    except json.JSONDecodeError as e:
        logger.error("Invalid config file: %s", e)
        raise ConfigError(f"Invalid config file: {e}")
    except Exception as e:
        logger.error("Failed to load agent: %s", e)
        raise JacsError(f"Failed to load agent: {e}")


class _EphemeralAgentAdapter:
    """Adapter that wraps a native SimpleAgent to provide the JacsAgent-compatible
    interface expected by the simple.py module functions.

    The simple.py functions call JacsAgent methods (create_document, verify_document,
    verify_agent, etc.) on the global agent. The native SimpleAgent has a different
    API (sign_message, verify, verify_self, etc.). This adapter bridges the gap.
    """

    def __init__(self, native_agent):
        self._native = native_agent

    def verify_agent(self, agentfile=None):
        """Delegate to SimpleAgent.verify_self(); returns True or raises."""
        result = self._native.verify_self()
        if not result.get("valid", False):
            errors = result.get("errors", [])
            raise RuntimeError(f"Agent verification failed: {errors}")
        return True

    def create_document(self, document_string, custom_schema=None,
                        outputfilename=None, no_save=None, attachments=None,
                        embed=None):
        """Delegate to SimpleAgent.sign_message() for message signing,
        or sign_file() for file attachments."""
        if attachments:
            result = self._native.sign_file(attachments, embed or False)
        else:
            # Parse the document JSON and sign the value
            data = json.loads(document_string)
            result = self._native.sign_message(data)
        return result.get("raw", "")

    @staticmethod
    def _unwrap_jacs_payload(data):
        """Extract original request payload from JACS wrapper structures."""
        if not isinstance(data, dict):
            return data

        if "jacs_payload" in data:
            return data.get("jacs_payload")

        jacs_document = data.get("jacsDocument")
        if isinstance(jacs_document, dict) and "jacs_payload" in jacs_document:
            return jacs_document.get("jacs_payload")

        payload = data.get("payload")
        if isinstance(payload, dict) and "jacs_payload" in payload:
            return payload.get("jacs_payload")

        return data

    def sign_request(self, payload):
        """JacsAgent-compatible request signing used by A2A integration."""
        result = self._native.sign_message({"jacs_payload": payload})

        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            raw = result.get("raw") or result.get("raw_json")
            if isinstance(raw, str):
                return raw
        raise RuntimeError("Ephemeral sign_request returned an unexpected result shape")

    def verify_response(self, document_string):
        """JacsAgent-compatible response verification used by A2A integration."""
        result = self._native.verify(document_string)
        if not isinstance(result, dict):
            raise RuntimeError("Ephemeral verify_response returned an unexpected result shape")

        if not result.get("valid", False):
            errors = result.get("errors")
            if isinstance(errors, list) and errors:
                message = "; ".join(str(e) for e in errors)
            elif errors:
                message = str(errors)
            else:
                message = "signature verification failed"
            raise RuntimeError(message)

        return self._unwrap_jacs_payload(result.get("data"))

    def verify_document(self, document_string):
        """Delegate to SimpleAgent.verify()."""
        result = self._native.verify(document_string)
        return result.get("valid", False)

    def get_agent_json(self):
        """Delegate to SimpleAgent.export_agent()."""
        return self._native.export_agent()

    def update_agent(self, new_agent_string):
        raise JacsError(
            "update_agent() is not supported on ephemeral agents. "
            "Use jacs.create() or jacs.load() for a persistent agent."
        )

    def update_document(self, document_key, new_document_string,
                        attachments=None, embed=None):
        raise JacsError(
            "update_document() is not supported on ephemeral agents. "
            "Use jacs.create() or jacs.load() for a persistent agent."
        )

    def create_agreement(self, document_string, agentids, question=None,
                         context=None, agreement_fieldname=None):
        raise JacsError(
            "create_agreement() is not supported on ephemeral agents. "
            "Use jacs.create() or jacs.load() for a persistent agent."
        )

    def sign_agreement(self, document_string, agreement_fieldname=None):
        raise JacsError(
            "sign_agreement() is not supported on ephemeral agents. "
            "Use jacs.create() or jacs.load() for a persistent agent."
        )

    def check_agreement(self, document_string, agreement_fieldname=None):
        raise JacsError(
            "check_agreement() is not supported on ephemeral agents. "
            "Use jacs.create() or jacs.load() for a persistent agent."
        )

    def verify_document_by_id(self, document_id):
        result = self._native.verify_by_id(document_id)
        return result.get("valid", False)

    def reencrypt_key(self, old_password, new_password):
        return self._native.reencrypt_key(old_password, new_password)

    def diagnostics(self):
        return json.dumps({"agent_loaded": True, "ephemeral": True})

    def get_setup_instructions(self, domain, ttl=3600):
        raise JacsError(
            "get_setup_instructions() is not supported on ephemeral agents. "
            "Use jacs.create() or jacs.load() for a persistent agent."
        )



def quickstart(algorithm=None, strict=None, config_path=None):
    """One-line agent creation with persistent keys on disk.

    If a config file already exists, loads the existing agent. Otherwise,
    creates a new agent with keys on disk and a minimal config file.

    If JACS_PRIVATE_KEY_PASSWORD is not set, a secure password is auto-generated.
    Set JACS_SAVE_PASSWORD_FILE=true to also persist it to ./jacs_keys/.jacs_password.

    Example:
        import jacs.simple as jacs
        jacs.quickstart()
        signed = jacs.sign_message({"hello": "world"})

    Args:
        algorithm: "ed25519" (default), "rsa-pss", or "pq2025"
        strict: Enable strict verification mode
        config_path: Path to config file (default: "./jacs.config.json")

    Returns:
        AgentInfo with agent_id, name, algorithm, version
    """
    global _global_agent, _agent_info, _strict

    _strict = _resolve_strict(strict)
    cfg_path = config_path or "./jacs.config.json"

    try:
        if os.path.exists(cfg_path):
            # Load existing agent
            logger.info("quickstart: found existing config at %s, loading", cfg_path)
            return load(cfg_path, strict=strict)

        # No existing config -- create a new persistent agent
        logger.info("quickstart: no config at %s, creating new agent", cfg_path)

        # Ensure password is available
        password = os.environ.get("JACS_PRIVATE_KEY_PASSWORD", "")
        if not password:
            import secrets
            import string
            # Generate a secure password meeting JACS requirements
            chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
            password = (
                secrets.choice(string.ascii_uppercase)
                + secrets.choice(string.ascii_lowercase)
                + secrets.choice(string.digits)
                + secrets.choice("!@#$%^&*()-_=+")
                + ''.join(secrets.choice(chars) for _ in range(28))
            )
            persist_password = os.environ.get("JACS_SAVE_PASSWORD_FILE", "").lower() in ("1", "true")
            if persist_password:
                keys_dir = "./jacs_keys"
                os.makedirs(keys_dir, exist_ok=True)
                pw_path = os.path.join(keys_dir, ".jacs_password")
                with open(pw_path, "w", encoding="utf-8") as f:
                    f.write(password)
                os.chmod(pw_path, 0o600)
                logger.info("quickstart: generated password saved to %s", pw_path)
            os.environ["JACS_PRIVATE_KEY_PASSWORD"] = password

        algo = algorithm or "pq2025"
        return create(
            name="jacs-agent",
            password=password,
            algorithm=algo,
            config_path=cfg_path,
            strict=strict,
        )

    except ImportError:
        raise JacsError(
            "Quickstart requires the full JACS native module. "
            "Install with: pip install jacs"
        )
    except Exception as e:
        raise JacsError(f"quickstart failed: {e}")


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
        if _strict:
            raise VerificationError(f"Self-verification failed (strict mode): {e}") from e
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
    logger.debug("create_agreement() called with %d agent_ids", len(agent_ids))

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
        signed_doc = _parse_signed_document(result)
        logger.info("Agreement created: document_id=%s, signers=%s", signed_doc.document_id, agent_ids)
        return signed_doc
    except Exception as e:
        logger.error("Failed to create agreement: %s", e)
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
    logger.debug("sign_message() called with data type=%s", type(data).__name__)

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

        signed_doc = _parse_signed_document(result)
        logger.info("Message signed: document_id=%s", signed_doc.document_id)
        return signed_doc

    except Exception as e:
        logger.error("Failed to sign message: %s", e)
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


def verify_standalone(
    document: Union[str, dict],
    key_resolution: str = "local",
    data_directory: Optional[str] = None,
    key_directory: Optional[str] = None,
) -> VerificationResult:
    """Verify a signed JACS document without loading an agent.

    Does not use the global agent; uses caller-supplied key resolution
    and directories. Use this for one-off verification when you have
    a signed document string and key directories.

    Args:
        document: Signed JACS document (JSON string or dict)
        key_resolution: Key resolution order (default "local")
        data_directory: Optional path for data/trust store
        key_directory: Optional path for public keys

    Returns:
        VerificationResult with valid and signer_id

    Example:
        result = jacs.verify_standalone(signed_json, key_resolution="local", key_directory="./keys")
        if result.valid:
            print(f"Signed by: {result.signer_id}")
    """
    doc_str = json.dumps(document) if isinstance(document, dict) else document
    try:
        d = _verify_document_standalone(
            doc_str,
            key_resolution=key_resolution,
            data_directory=data_directory,
            key_directory=key_directory,
        )
        # Native returns dict with valid, signer_id
        return VerificationResult(
            valid=bool(d.get("valid", False)),
            signer_id=str(d.get("signer_id", "")),
        )
    except Exception as e:
        return VerificationResult(valid=False, errors=[str(e)])


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
    logger.debug("verify() called with document type=%s", type(document).__name__)

    # Convert to JSON string if needed
    if isinstance(document, SignedDocument):
        doc_str = document.raw_json
    elif isinstance(document, dict):
        doc_str = json.dumps(document)
    else:
        doc_str = document

    # Pre-check: if input doesn't look like JSON, give helpful error
    trimmed = doc_str.strip() if isinstance(doc_str, str) else ""
    if trimmed and not trimmed.startswith("{") and not trimmed.startswith("["):
        return VerificationResult(
            valid=False,
            errors=[
                f"Input does not appear to be a JSON document. "
                f"If you have a document ID (e.g., 'uuid:version'), "
                f"use verify_by_id() instead. Received: '{trimmed[:60]}'"
            ],
        )

    try:
        # Verify the document
        is_valid = agent.verify_document(doc_str)

        # Parse to get signer info
        doc_data = json.loads(doc_str)
        sig_info = doc_data.get("jacsSignature", {})
        signer_id = sig_info.get("agentId", sig_info.get("agentID", ""))

        logger.info("Document verified: valid=%s, signer=%s", is_valid, signer_id)

        return VerificationResult(
            valid=is_valid,
            signer_id=signer_id,
            signer_public_key_hash=sig_info.get("publicKeyHash", ""),
            content_hash_valid=is_valid,
            signature_valid=is_valid,
            timestamp=sig_info.get("date", ""),
        )

    except Exception as e:
        logger.warning("Verification failed: %s", e)
        if _strict:
            raise VerificationError(f"Verification failed (strict mode): {e}") from e
        return VerificationResult(
            valid=False,
            errors=[str(e)],
        )


def verify_by_id(document_id: str) -> VerificationResult:
    """Verify a signed document by its storage ID.

    This is a convenience function when you have a document ID (e.g., "uuid:version")
    rather than the full JSON document string.

    Args:
        document_id: Document ID in "uuid:version" format

    Returns:
        VerificationResult with verification status

    Raises:
        AgentNotLoadedError: If no agent is loaded
        JacsError: If the document is not found or verification fails

    Example:
        result = jacs.verify_by_id("550e8400-e29b-41d4:1")
        if result.valid:
            print(f"Document verified, signed by: {result.signer_id}")
    """
    agent = _get_agent()
    logger.debug("verify_by_id() called with document_id=%s", document_id)

    # Pre-check format
    if ":" not in document_id:
        raise JacsError(
            f"Document ID must be in 'uuid:version' format, got '{document_id}'. "
            "Use verify() with the full JSON document string instead."
        )

    try:
        is_valid = agent.verify_document_by_id(document_id)
        doc_data = _read_document_by_id(document_id)
        signer_id, signer_public_key_hash, timestamp = _extract_signature_metadata(doc_data)

        return VerificationResult(
            valid=is_valid,
            signer_id=signer_id,
            signer_public_key_hash=signer_public_key_hash,
            content_hash_valid=is_valid,
            signature_valid=is_valid,
            timestamp=timestamp,
        )
    except Exception as e:
        logger.warning("verify_by_id failed: %s", e)
        if _strict:
            raise VerificationError(f"Verification failed (strict mode): {e}") from e
        return VerificationResult(
            valid=False,
            errors=[str(e)],
        )


def reencrypt_key(old_password: str, new_password: str) -> None:
    """Re-encrypt the agent's private key with a new password.

    This decrypts the private key with the old password, validates the new
    password meets requirements, and re-encrypts with the new password.

    Args:
        old_password: The current password protecting the private key
        new_password: The new password (must meet password requirements)

    Raises:
        AgentNotLoadedError: If no agent is loaded
        JacsError: If re-encryption fails (wrong old password, weak new password, etc.)

    Example:
        jacs.load("./jacs.config.json")
        jacs.reencrypt_key("OldP@ss123!", "NewStr0ng!Pass#2025")
        print("Key re-encrypted successfully")
    """
    logger.debug("reencrypt_key() called")

    try:
        agent = _get_agent()
        agent.reencrypt_key(old_password, new_password)
        logger.info("Private key re-encrypted successfully")
    except Exception as e:
        raise JacsError(f"Failed to re-encrypt key: {e}")


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

    # Try loaded agent metadata first, then config-derived fallbacks.
    try:
        key_candidates: List[str] = []
        if _agent_info.public_key_path:
            key_candidates.append(_agent_info.public_key_path)
        if _agent_info.config_path and os.path.exists(_agent_info.config_path):
            with open(_agent_info.config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            config_path = os.path.abspath(_agent_info.config_path)
            key_dir = _resolve_config_relative_path(
                config_path, config.get("jacs_key_directory", "./jacs_keys")
            )
            key_file = config.get("jacs_agent_public_key_filename", "jacs.public.pem")
            key_candidates.append(os.path.join(key_dir, key_file))

        for candidate in key_candidates:
            if os.path.exists(candidate):
                with open(candidate, "r", encoding="utf-8") as f:
                    return f.read()

        raise JacsError(f"Could not find public key file in: {key_candidates}")

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
    agent = _get_agent()

    try:
        return agent.get_agent_json()
    except Exception as e:
        raise JacsError(f"Failed to export agent: {e}")


def get_dns_record(domain: str, ttl: int = 3600) -> str:
    """Return the DNS TXT record line for the loaded agent (for DNS-based discovery).

    Format: _v1.agent.jacs.{domain}. TTL IN TXT "v=jacs; jacs_agent_id=...; ..."

    Args:
        domain: The domain (e.g. "example.com")
        ttl: TTL in seconds (default 3600)

    Returns:
        The full DNS record line
    """
    agent = _get_agent()
    agent_doc = json.loads(agent.get_agent_json())
    jacs_id = agent_doc.get("jacsId") or agent_doc.get("agentId") or ""
    sig = agent_doc.get("jacsSignature") or {}
    public_key_hash = sig.get("publicKeyHash") or ""
    d = domain.rstrip(".")
    owner = f"_v1.agent.jacs.{d}."
    txt = f"v=jacs; jacs_agent_id={jacs_id}; alg=SHA-256; enc=base64; jac_public_key_hash={public_key_hash}"
    return f'{owner} {ttl} IN TXT "{txt}"'


def get_well_known_json() -> dict:
    """Return the well-known JSON object for the loaded agent (e.g. for /.well-known/jacs-pubkey.json).

    Keys: publicKey, publicKeyHash, algorithm, agentId.
    """
    agent = _get_agent()
    agent_doc = json.loads(agent.get_agent_json())
    jacs_id = agent_doc.get("jacsId") or agent_doc.get("agentId") or ""
    sig = agent_doc.get("jacsSignature") or {}
    public_key_hash = sig.get("publicKeyHash") or ""
    try:
        public_key = get_public_key()
    except Exception:
        public_key = ""
    return {
        "publicKey": public_key,
        "publicKeyHash": public_key_hash,
        "algorithm": "SHA-256",
        "agentId": jacs_id,
    }


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


def debug_info() -> dict:
    """Return JACS diagnostic info (version, config, agent status).

    Returns a dict with keys like jacs_version, os, arch, agent_loaded,
    data_directory, key_directory, etc. If an agent is loaded, includes
    agent_id and agent_version.

    Returns:
        dict with diagnostic information
    """
    if _global_agent is not None:
        try:
            return json.loads(_global_agent.diagnostics())
        except Exception:
            pass
    return {"jacs_version": "unknown", "agent_loaded": False}


def trust_agent(agent_json: str) -> str:
    """Add an agent to the local trust store.

    Args:
        agent_json: The full agent JSON document string

    Returns:
        The trusted agent's ID

    Raises:
        TrustError: If the agent document is invalid

    Example:
        agent_id = jacs.trust_agent(remote_agent_json)
        print(f"Trusted: {agent_id}")
    """
    try:
        return _trust_agent(agent_json)
    except Exception as e:
        raise TrustError(f"Failed to trust agent: {e}")


def list_trusted_agents() -> List[str]:
    """List all trusted agent IDs in the local trust store.

    Returns:
        List of agent UUID strings

    Example:
        for agent_id in jacs.list_trusted_agents():
            print(agent_id)
    """
    try:
        return _list_trusted_agents()
    except Exception as e:
        raise TrustError(f"Failed to list trusted agents: {e}")


def untrust_agent(agent_id: str) -> None:
    """Remove an agent from the local trust store.

    Args:
        agent_id: The UUID of the agent to remove

    Raises:
        TrustError: If the agent is not in the trust store

    Example:
        jacs.untrust_agent("550e8400-e29b-41d4-a716-446655440000")
    """
    try:
        _untrust_agent(agent_id)
    except Exception as e:
        raise TrustError(f"Failed to untrust agent: {e}")


def is_trusted(agent_id: str) -> bool:
    """Check if an agent is in the local trust store.

    Args:
        agent_id: The UUID of the agent to check

    Returns:
        True if the agent is trusted

    Example:
        if jacs.is_trusted(sender_id):
            print("Agent is trusted")
    """
    return _is_trusted(agent_id)


def get_trusted_agent(agent_id: str) -> str:
    """Get a trusted agent's full JSON document from the trust store.

    Args:
        agent_id: The UUID of the agent to retrieve

    Returns:
        The agent's JSON document as a string

    Raises:
        TrustError: If the agent is not in the trust store

    Example:
        agent_json = jacs.get_trusted_agent(agent_id)
        agent_data = json.loads(agent_json)
    """
    try:
        return _get_trusted_agent(agent_id)
    except Exception as e:
        raise TrustError(f"Failed to get trusted agent: {e}")


def audit(
    config_path: Optional[str] = None,
    recent_n: Optional[int] = None,
) -> dict:
    """Run a read-only security audit and health checks.

    Returns a dict with risks, health_checks, summary, and related fields.
    Does not modify state. When invoked from CLI, a human-readable report
    can be printed; use this function to get the structured result.

    Args:
        config_path: Optional path to jacs config file.
        recent_n: Optional number of recent documents to re-verify.

    Returns:
        Dict with keys including "risks", "health_checks", "summary", "overall_status".

    Example:
        result = jacs.audit()
        print(f"Risks: {len(result['risks'])}, Status: {result['overall_status']}")
    """
    try:
        json_str = _audit(config_path=config_path, recent_n=recent_n)
        return json.loads(json_str)
    except Exception as e:
        raise JacsError(f"Audit failed: {e}") from e


def verify_dns(
    agent_document: Union[str, dict],
    domain: str,
) -> VerificationResult:
    """Verify an agent's identity via DNS TXT record lookup.

    Checks that the agent's public key hash published in a DNS TXT record
    at _v1.agent.jacs.{domain} matches the key in the agent document.

    Args:
        agent_document: The agent document to verify (JSON string or dict).
        domain: The domain to look up (e.g. "example.com").

    Returns:
        VerificationResult with valid=True if DNS record matches.
    """
    doc_str = json.dumps(agent_document) if isinstance(agent_document, dict) else agent_document
    try:
        d = _verify_agent_dns(doc_str, domain)
        return VerificationResult(
            valid=bool(d.get("verified", False)),
            signer_id=str(d.get("agent_id", "")),
            errors=[d["message"]] if not d.get("verified") and d.get("message") else [],
        )
    except Exception as e:
        return VerificationResult(valid=False, errors=[str(e)])


def get_setup_instructions(domain: str, ttl: int = 3600) -> dict:
    """Get comprehensive setup instructions for DNS and DNSSEC.

    Returns structured data with provider-specific commands for AWS Route53,
    Cloudflare, Azure DNS, Google Cloud DNS, and plain BIND format. Also includes
    DNSSEC guidance, well-known JSON payload, and a human-readable summary.

    Args:
        domain: The domain to publish the DNS TXT record under.
        ttl: TTL in seconds for the DNS record (default: 3600).

    Returns:
        Dict with keys: dns_record_bind, dns_record_value, dns_owner,
        provider_commands, dnssec_instructions, tld_requirement, well_known_json,
        summary.

    Example:
        instructions = jacs.get_setup_instructions("example.com")
        print(instructions["summary"])
        print(instructions["provider_commands"]["route53"])
    """
    agent = _get_agent()
    try:
        json_str = agent.get_setup_instructions(domain, ttl)
        return json.loads(json_str)
    except Exception as e:
        raise JacsError(f"Failed to get setup instructions: {e}") from e


__all__ = [
    # Core operations
    "quickstart",
    "create",
    "load",
    "verify_self",
    "update_agent",
    "update_document",
    "sign_message",
    "sign_file",
    "verify",
    "verify_by_id",
    "reencrypt_key",
    # Agreement functions
    "create_agreement",
    "sign_agreement",
    "check_agreement",
    # Standalone verification
    "verify_standalone",
    "verify_dns",
    # Utility functions
    "get_public_key",
    "export_agent",
    "get_dns_record",
    "get_well_known_json",
    "get_agent_info",
    "is_loaded",
    # Trust store
    "trust_agent",
    "list_trusted_agents",
    "untrust_agent",
    "is_trusted",
    "get_trusted_agent",
    # Diagnostics
    "debug_info",
    # Strict mode
    "is_strict",
    # Test utilities
    "reset",
    # Setup
    "get_setup_instructions",
    # Types (re-exported for convenience)
    "AgentInfo",
    "Attachment",
    "SignedDocument",
    "VerificationResult",
    "SignerStatus",
    "AgreementStatus",
    "PublicKeyInfo",
    # Errors
    "JacsError",
    "ConfigError",
    "AgentNotLoadedError",
    "SigningError",
    "VerificationError",
    "TrustError",
    "KeyNotFoundError",
    "NetworkError",
]
