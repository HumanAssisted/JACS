"""
JACS Type Definitions

Python dataclasses that mirror the Rust simple API types.
These provide type hints and structure for the simplified API.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class AgentInfo:
    """Information about a loaded JACS agent.

    Attributes:
        agent_id: Unique identifier for the agent (UUID format)
        version: Agent version string
        name: Optional human-readable agent name
        public_key_hash: Hash of the agent's public key for verification
        created_at: ISO 8601 timestamp of agent creation
        algorithm: Cryptographic algorithm used (e.g., "RSA", "ML-DSA")
        config_path: Path to the loaded config file
        public_key_path: Path to the public key file
    """
    agent_id: str
    version: str
    name: Optional[str] = None
    public_key_hash: str = ""
    created_at: str = ""
    algorithm: str = "RSA"
    config_path: Optional[str] = None
    public_key_path: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentInfo":
        """Create AgentInfo from a dictionary."""
        return cls(
            agent_id=data.get("agent_id", ""),
            version=data.get("version", ""),
            name=data.get("name"),
            public_key_hash=data.get("public_key_hash", ""),
            created_at=data.get("created_at", ""),
            algorithm=data.get("algorithm", "RSA"),
            config_path=data.get("config_path"),
            public_key_path=data.get("public_key_path"),
        )


@dataclass
class Attachment:
    """File attachment with content hash for integrity verification.

    Attributes:
        filename: Original filename
        mime_type: MIME type of the content
        content_hash: SHA-256 hash of the file content
        content: Base64-encoded file content (if embedded)
        size_bytes: Size of the original file in bytes
    """
    filename: str
    mime_type: str
    content_hash: str
    content: Optional[str] = None
    size_bytes: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Attachment":
        """Create Attachment from a dictionary."""
        return cls(
            filename=data.get("filename", ""),
            mime_type=data.get("mime_type", "application/octet-stream"),
            content_hash=data.get("content_hash", ""),
            content=data.get("content"),
            size_bytes=data.get("size_bytes", 0),
        )


@dataclass
class SignedDocument:
    """A cryptographically signed JACS document.

    Attributes:
        document_id: Unique document identifier
        version: Document version
        content_hash: Hash of the document content for integrity verification
        signature: Base64-encoded cryptographic signature
        signer_id: ID of the agent that signed the document
        signed_at: ISO 8601 timestamp when the document was signed
        payload: The signed content (message text or structured data)
        attachments: List of file attachments (for file signing)
        raw_json: The complete JSON document as a string
    """
    document_id: str
    version: str
    content_hash: str
    signature: str
    signer_id: str
    signed_at: str
    payload: Any = None
    attachments: List[Attachment] = field(default_factory=list)
    raw_json: str = ""

    @property
    def raw(self) -> str:
        """Alias for raw_json (for API consistency with Node.js)."""
        return self.raw_json

    @property
    def agent_id(self) -> str:
        """Alias for signer_id (for API consistency with Node.js)."""
        return self.signer_id

    @property
    def timestamp(self) -> str:
        """Alias for signed_at (for API consistency with Node.js)."""
        return self.signed_at

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignedDocument":
        """Create SignedDocument from a dictionary."""
        attachments = [
            Attachment.from_dict(a) if isinstance(a, dict) else a
            for a in data.get("attachments", [])
        ]
        return cls(
            document_id=data.get("document_id", data.get("id", "")),
            version=data.get("version", ""),
            content_hash=data.get("content_hash", ""),
            signature=data.get("signature", ""),
            signer_id=data.get("signer_id", ""),
            signed_at=data.get("signed_at", ""),
            payload=data.get("payload"),
            attachments=attachments,
            raw_json=data.get("raw_json", ""),
        )

    def to_json(self) -> str:
        """Return the raw JSON representation of the signed document."""
        return self.raw_json


@dataclass
class VerificationResult:
    """Result of verifying a signed document or agent.

    Attributes:
        valid: True if verification succeeded
        signer_id: ID of the signing agent
        signer_public_key_hash: Hash of the signer's public key
        content_hash_valid: True if content hash matches
        signature_valid: True if cryptographic signature is valid
        timestamp: When the document was signed (ISO 8601)
        errors: List of error messages if verification failed
        attachments: List of file attachments in the document
    """
    valid: bool
    signer_id: str = ""
    signer_public_key_hash: str = ""
    content_hash_valid: bool = False
    signature_valid: bool = False
    timestamp: str = ""
    errors: List[str] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)

    @property
    def error(self) -> Optional[str]:
        """Return first error message (for backwards compatibility)."""
        return self.errors[0] if self.errors else None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerificationResult":
        """Create VerificationResult from a dictionary."""
        errors = data.get("errors", [])
        if not errors and data.get("error"):
            errors = [data.get("error")]
        attachments = [
            Attachment.from_dict(a) if isinstance(a, dict) else a
            for a in data.get("attachments", [])
        ]
        return cls(
            valid=data.get("valid", False),
            signer_id=data.get("signer_id", ""),
            signer_public_key_hash=data.get("signer_public_key_hash", ""),
            content_hash_valid=data.get("content_hash_valid", False),
            signature_valid=data.get("signature_valid", False),
            timestamp=data.get("timestamp", ""),
            errors=errors,
            attachments=attachments,
        )

    @classmethod
    def success(
        cls,
        signer_id: str,
        public_key_hash: str,
        timestamp: str = ""
    ) -> "VerificationResult":
        """Create a successful verification result."""
        return cls(
            valid=True,
            signer_id=signer_id,
            signer_public_key_hash=public_key_hash,
            content_hash_valid=True,
            signature_valid=True,
            timestamp=timestamp,
        )

    @classmethod
    def failure(cls, error: str) -> "VerificationResult":
        """Create a failed verification result."""
        return cls(
            valid=False,
            errors=[error] if error else [],
        )


# Error types for better error handling
class JacsError(Exception):
    """Base exception for JACS errors."""
    pass


class ConfigError(JacsError):
    """Configuration file not found or invalid."""
    pass


class AgentNotLoadedError(JacsError):
    """No agent is currently loaded."""
    pass


class SigningError(JacsError):
    """Failed to sign a document or message."""
    pass


class VerificationError(JacsError):
    """Signature or hash verification failed."""
    pass


class TrustError(JacsError):
    """Trust store operation failed."""
    pass


@dataclass
class SignerStatus:
    """Status of a single signer in a multi-party agreement.

    Attributes:
        agent_id: Unique identifier of the signing agent
        signed: Whether this agent has signed the agreement
        signed_at: ISO 8601 timestamp when the agent signed (if signed)
    """
    agent_id: str
    signed: bool
    signed_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignerStatus":
        """Create SignerStatus from a dictionary."""
        return cls(
            agent_id=data.get("agent_id", data.get("agentId", "")),
            signed=data.get("signed", False),
            signed_at=data.get("signed_at", data.get("signedAt")),
        )


@dataclass
class AgreementStatus:
    """Status of a multi-party agreement.

    Attributes:
        complete: Whether all required parties have signed
        signers: List of signer statuses
        pending: List of agent IDs that haven't signed yet
    """
    complete: bool
    signers: List[SignerStatus]
    pending: List[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgreementStatus":
        """Create AgreementStatus from a dictionary."""
        signers = [
            SignerStatus.from_dict(s) if isinstance(s, dict) else s
            for s in data.get("signers", [])
        ]
        return cls(
            complete=data.get("complete", False),
            signers=signers,
            pending=data.get("pending", []),
        )


__all__ = [
    "AgentInfo",
    "Attachment",
    "SignedDocument",
    "VerificationResult",
    "SignerStatus",
    "AgreementStatus",
    "JacsError",
    "ConfigError",
    "AgentNotLoadedError",
    "SigningError",
    "VerificationError",
    "TrustError",
]
