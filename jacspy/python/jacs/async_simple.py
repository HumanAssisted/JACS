"""
JACS Async Simplified API

Async wrappers for the JACS simple API, designed for use with FastAPI,
aiohttp, and other async Python frameworks.

All functions mirror the synchronous simple API but are awaitable.
Under the hood, they use asyncio.to_thread() to run blocking operations
in a thread pool, ensuring they don't block the event loop.

Example:
    import asyncio
    import jacs.async_simple as jacs

    async def main():
        # Load agent
        agent_info = await jacs.load("./jacs.config.json")

        # Sign a message
        signed = await jacs.sign_message("Hello, World!")
        print(signed.document_id)

        # Verify it
        result = await jacs.verify(signed.raw_json)
        print(f"Valid: {result.valid}")

        # Create and manage agreements
        agreement = await jacs.create_agreement(
            document={"proposal": "Async proposal"},
            agent_ids=["agent-1", "agent-2"]
        )
        status = await jacs.check_agreement(agreement)
        print(f"Complete: {status.complete}")

    asyncio.run(main())

FastAPI Example:
    from fastapi import FastAPI
    import jacs.async_simple as jacs

    app = FastAPI()

    @app.on_event("startup")
    async def startup():
        await jacs.load("./jacs.config.json")

    @app.post("/sign")
    async def sign_data(data: dict):
        signed = await jacs.sign_message(data)
        return {"document_id": signed.document_id, "raw": signed.raw_json}

    @app.post("/verify")
    async def verify_data(document: str):
        result = await jacs.verify(document)
        return {"valid": result.valid, "signer": result.signer_id}
"""

import asyncio
from typing import Optional, Union, List, Any

# Import sync functions and types from simple module
from . import simple
from .types import (
    AgentInfo,
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


# =============================================================================
# Core Operations
# =============================================================================


async def create(
    name: Optional[str] = None,
    agent_type: str = "service",
    algorithm: str = "pq2025",
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
        agent = await jacs.create(name="My Agent")
        print(f"Created agent: {agent.agent_id}")
    """
    return await asyncio.to_thread(
        simple.create,
        name,
        agent_type,
        algorithm,
        config_path,
    )


async def load(config_path: Optional[str] = None) -> AgentInfo:
    """Load an existing JACS agent from configuration.

    Args:
        config_path: Path to jacs.config.json (default: ./jacs.config.json)

    Returns:
        AgentInfo with the loaded agent's details

    Raises:
        ConfigError: If config file not found or invalid
        JacsError: If agent loading fails

    Example:
        agent = await jacs.load("./jacs.config.json")
        print(f"Loaded: {agent.name}")
    """
    return await asyncio.to_thread(simple.load, config_path)


async def verify_self() -> VerificationResult:
    """Verify the currently loaded agent's integrity.

    Checks both the cryptographic signature and content hash
    of the loaded agent document.

    Returns:
        VerificationResult indicating if the agent is valid

    Raises:
        AgentNotLoadedError: If no agent is loaded

    Example:
        result = await jacs.verify_self()
        if result.valid:
            print("Agent integrity verified")
        else:
            print(f"Error: {result.error}")
    """
    return await asyncio.to_thread(simple.verify_self)


async def update_agent(new_agent_data: Union[str, dict]) -> str:
    """Update the agent document with new data and re-sign it.

    This function expects a complete agent document (not partial updates).
    Use export_agent() to get the current document, modify it, then pass it here.

    Args:
        new_agent_data: Complete agent document as JSON string or dict

    Returns:
        The updated and re-signed agent document as a JSON string

    Raises:
        AgentNotLoadedError: If no agent is loaded
        JacsError: If update fails

    Example:
        agent_doc = json.loads(await jacs.export_agent())
        agent_doc["jacsAgentType"] = "updated-service"
        updated = await jacs.update_agent(agent_doc)
    """
    return await asyncio.to_thread(simple.update_agent, new_agent_data)


async def update_document(
    document_id: str,
    new_document_data: Union[str, dict],
    attachments: Optional[List[str]] = None,
    embed: bool = False,
) -> SignedDocument:
    """Update an existing document with new data and re-sign it.

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
        signed = await jacs.sign_message({"status": "pending"})
        doc = json.loads(signed.raw_json)
        doc["content"]["status"] = "approved"
        updated = await jacs.update_document(signed.document_id, doc)
    """
    return await asyncio.to_thread(
        simple.update_document,
        document_id,
        new_document_data,
        attachments,
        embed,
    )


# =============================================================================
# Signing Operations
# =============================================================================


async def sign_message(data: Any) -> SignedDocument:
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
        signed = await jacs.sign_message({"action": "approve", "amount": 100})
        print(signed.document_id)
    """
    return await asyncio.to_thread(simple.sign_message, data)


async def sign_file(
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
        signed = await jacs.sign_file("contract.pdf", embed=True)
        print(f"Signed {signed.attachments[0].filename}")
    """
    return await asyncio.to_thread(simple.sign_file, file_path, embed, mime_type)


# =============================================================================
# Verification Operations
# =============================================================================


async def verify(document: Union[str, dict, SignedDocument]) -> VerificationResult:
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
        result = await jacs.verify(signed_json)
        if result.valid:
            print(f"Signed by: {result.signer_id}")
        else:
            print(f"Invalid: {result.error}")
    """
    return await asyncio.to_thread(simple.verify, document)


# =============================================================================
# Agreement Operations
# =============================================================================


async def create_agreement(
    document: Union[str, dict, SignedDocument],
    agent_ids: List[str],
    question: Optional[str] = None,
    context: Optional[str] = None,
    field_name: Optional[str] = None,
) -> SignedDocument:
    """Create a multi-party agreement requiring signatures from specified agents.

    This creates an agreement on a document that must be signed by all specified
    agents before it is considered complete.

    Args:
        document: The document to create an agreement on
        agent_ids: List of agent IDs required to sign the agreement
        question: Optional question or purpose of the agreement
        context: Optional additional context for signers
        field_name: Optional custom field name for the agreement

    Returns:
        SignedDocument containing the agreement document

    Raises:
        AgentNotLoadedError: If no agent is loaded
        JacsError: If agreement creation fails

    Example:
        agreement = await jacs.create_agreement(
            document={"proposal": "Merge codebases"},
            agent_ids=["agent-1-uuid", "agent-2-uuid"],
            question="Do you approve this merge?"
        )
    """
    return await asyncio.to_thread(
        simple.create_agreement,
        document,
        agent_ids,
        question,
        context,
        field_name,
    )


async def sign_agreement(
    document: Union[str, dict, SignedDocument],
    field_name: Optional[str] = None,
) -> SignedDocument:
    """Sign an existing multi-party agreement as the current agent.

    Args:
        document: The agreement document to sign
        field_name: Optional custom field name for the agreement

    Returns:
        SignedDocument with this agent's signature added

    Raises:
        AgentNotLoadedError: If no agent is loaded
        JacsError: If signing fails

    Example:
        signed = await jacs.sign_agreement(agreement_doc)
    """
    return await asyncio.to_thread(simple.sign_agreement, document, field_name)


async def check_agreement(
    document: Union[str, dict, SignedDocument],
    field_name: Optional[str] = None,
) -> AgreementStatus:
    """Check the status of a multi-party agreement.

    Args:
        document: The agreement document to check
        field_name: Optional custom field name for the agreement

    Returns:
        AgreementStatus with completion status and signer details

    Raises:
        AgentNotLoadedError: If no agent is loaded
        JacsError: If checking fails

    Example:
        status = await jacs.check_agreement(agreement_doc)
        if status.complete:
            print("All parties have signed!")
        else:
            print(f"Waiting for: {status.pending}")
    """
    return await asyncio.to_thread(simple.check_agreement, document, field_name)


# =============================================================================
# Utility Functions
# =============================================================================


async def get_public_key() -> str:
    """Get the loaded agent's public key in PEM format.

    Returns:
        The public key as a PEM-encoded string

    Raises:
        AgentNotLoadedError: If no agent is loaded

    Example:
        pem = await jacs.get_public_key()
        print(pem)
    """
    return await asyncio.to_thread(simple.get_public_key)


async def export_agent() -> str:
    """Export the agent document for sharing.

    Returns the complete agent JSON document that can be shared
    with other parties for trust establishment.

    Returns:
        The agent JSON document as a string

    Raises:
        AgentNotLoadedError: If no agent is loaded

    Example:
        agent_json = await jacs.export_agent()
    """
    return await asyncio.to_thread(simple.export_agent)


def get_agent_info() -> Optional[AgentInfo]:
    """Get information about the currently loaded agent.

    Note: This is synchronous as it only reads cached state.

    Returns:
        AgentInfo if an agent is loaded, None otherwise
    """
    return simple.get_agent_info()


def is_loaded() -> bool:
    """Check if an agent is currently loaded.

    Note: This is synchronous as it only reads cached state.

    Returns:
        True if an agent is loaded, False otherwise
    """
    return simple.is_loaded()


__all__ = [
    # Core operations
    "create",
    "load",
    "verify_self",
    "update_agent",
    "update_document",
    # Signing
    "sign_message",
    "sign_file",
    # Verification
    "verify",
    # Agreements
    "create_agreement",
    "sign_agreement",
    "check_agreement",
    # Utilities
    "get_public_key",
    "export_agent",
    "get_agent_info",
    "is_loaded",
    # Types (re-exported for convenience)
    "AgentInfo",
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
