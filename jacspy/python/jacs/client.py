"""
JACS Client — Instance-based API

A class-based interface that wraps its own JacsAgent, allowing multiple
clients to coexist in a single process without shared global state.

Example:
    from jacs.client import JacsClient

    client = JacsClient.quickstart()
    signed = client.sign_message({"hello": "world"})
    result = client.verify(signed.raw_json)
    assert result.valid
"""

import json
import logging
import os
from typing import Any, List, Optional, Union

from .types import (
    AgentInfo,
    AgreementStatus,
    Attachment,
    JacsError,
    ConfigError,
    AgentNotLoadedError,
    SignedDocument,
    SignerStatus,
    SigningError,
    VerificationError,
    VerificationResult,
)

logger = logging.getLogger("jacs.client")

# ---------------------------------------------------------------------------
# Rust binding imports (same pattern as simple.py)
# ---------------------------------------------------------------------------
try:
    from . import JacsAgent as _JacsAgent
    from . import SimpleAgent as _SimpleAgent
    from .jacs import trust_agent as _trust_agent
    from .jacs import list_trusted_agents as _list_trusted_agents
    from .jacs import untrust_agent as _untrust_agent
    from .jacs import is_trusted as _is_trusted
    from .jacs import get_trusted_agent as _get_trusted_agent
    from .jacs import audit as _audit
except ImportError:
    import jacs as _jacs_module  # type: ignore[no-redef]

    _JacsAgent = _jacs_module.JacsAgent  # type: ignore[misc]
    _SimpleAgent = _jacs_module.SimpleAgent  # type: ignore[misc]
    _trust_agent = _jacs_module.trust_agent
    _list_trusted_agents = _jacs_module.list_trusted_agents
    _untrust_agent = _jacs_module.untrust_agent
    _is_trusted = _jacs_module.is_trusted
    _get_trusted_agent = _jacs_module.get_trusted_agent
    _audit = _jacs_module.audit


def _resolve_strict(explicit: Optional[bool]) -> bool:
    if explicit is not None:
        return explicit
    return os.environ.get("JACS_STRICT_MODE", "").lower() in ("true", "1")


def _parse_signed_document(json_str: str) -> SignedDocument:
    """Parse a raw JSON string returned by Rust into a SignedDocument."""
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise JacsError(f"Invalid JSON document: {e}")

    doc_id = data.get("id", data.get("jacsId", ""))
    version = data.get("jacsVersion", data.get("version", ""))
    sig_info = data.get("jacsSignature", {})
    hash_info = data.get("jacsHash", {})

    attachments = []
    for f in data.get("jacsFiles", []):
        attachments.append(
            Attachment(
                filename=f.get("filename", ""),
                mime_type=f.get("mimeType", "application/octet-stream"),
                content_hash=f.get("sha256", ""),
                content=f.get("content"),
                size_bytes=f.get("size", 0),
            )
        )

    return SignedDocument(
        document_id=doc_id,
        version=version,
        content_hash=hash_info.get("hash", ""),
        signature=sig_info.get("signature", ""),
        signer_id=sig_info.get("agentId", sig_info.get("agentID", "")),
        signed_at=sig_info.get("date", ""),
        payload=data.get("jacsDocument", data.get("payload", data)),
        attachments=attachments,
        raw_json=json_str,
    )


class JacsClient:
    """Instance-based JACS client.

    Each JacsClient wraps its own JacsAgent — no global state is shared.
    Multiple clients can coexist in a single Python process.

    Usage:
        client = JacsClient("./jacs.config.json")
        signed = client.sign_message({"key": "value"})
        result = client.verify(signed.raw_json)

    Context manager:
        with JacsClient.quickstart() as client:
            signed = client.sign_message("hi")
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        algorithm: Optional[str] = None,
        strict: Optional[bool] = None,
    ) -> None:
        self._strict = _resolve_strict(strict)
        self._agent: _JacsAgent = _JacsAgent()
        self._agent_info: Optional[AgentInfo] = None

        if config_path is not None:
            self._load_from_config(config_path)

    # ------------------------------------------------------------------
    # Factory classmethods
    # ------------------------------------------------------------------

    @classmethod
    def quickstart(
        cls,
        algorithm: Optional[str] = None,
        config_path: Optional[str] = None,
        strict: Optional[bool] = None,
    ) -> "JacsClient":
        """Create or load an agent with minimal configuration.

        If a config file exists, it is loaded; otherwise a new persistent
        agent is created on disk (keys + config).
        """
        cfg_path = config_path or "./jacs.config.json"
        instance = cls.__new__(cls)
        instance._strict = _resolve_strict(strict)
        instance._agent = _JacsAgent()
        instance._agent_info = None

        if os.path.exists(cfg_path):
            instance._load_from_config(cfg_path)
            return instance

        # Create a new persistent agent via SimpleAgent
        password = os.environ.get("JACS_PRIVATE_KEY_PASSWORD", "")
        if not password:
            import secrets
            import string

            chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
            password = (
                secrets.choice(string.ascii_uppercase)
                + secrets.choice(string.ascii_lowercase)
                + secrets.choice(string.digits)
                + secrets.choice("!@#$%^&*()-_=+")
                + "".join(secrets.choice(chars) for _ in range(28))
            )
            keys_dir = "./jacs_keys"
            os.makedirs(keys_dir, exist_ok=True)
            pw_path = os.path.join(keys_dir, ".jacs_password")
            with open(pw_path, "w") as f:
                f.write(password)
            os.chmod(pw_path, 0o600)
            os.environ["JACS_PRIVATE_KEY_PASSWORD"] = password

        algo = algorithm or "pq2025"
        _SimpleAgent.create_agent(
            name="jacs-agent",
            password=password,
            algorithm=algo,
            data_directory="./jacs_data",
            key_directory="./jacs_keys",
            config_path=cfg_path,
            default_storage="fs",
        )

        prev_pw = os.environ.get("JACS_PRIVATE_KEY_PASSWORD")
        os.environ["JACS_PRIVATE_KEY_PASSWORD"] = password
        try:
            instance._load_from_config(cfg_path)
        finally:
            if prev_pw is None:
                os.environ.pop("JACS_PRIVATE_KEY_PASSWORD", None)
            else:
                os.environ["JACS_PRIVATE_KEY_PASSWORD"] = prev_pw

        return instance

    @classmethod
    def ephemeral(
        cls,
        algorithm: Optional[str] = None,
        strict: Optional[bool] = None,
    ) -> "JacsClient":
        """Create an ephemeral in-memory client (no files, no env vars).

        Ideal for tests.
        """
        instance = cls.__new__(cls)
        instance._strict = _resolve_strict(strict)

        native_agent, info_dict = _SimpleAgent.ephemeral(algorithm)
        # Wrap the SimpleAgent in an _EphemeralAgentAdapter so the
        # JacsClient methods that call JacsAgent APIs still work.
        from .simple import _EphemeralAgentAdapter

        instance._agent = _EphemeralAgentAdapter(native_agent)
        instance._agent_info = AgentInfo(
            agent_id=info_dict.get("agent_id", ""),
            version=info_dict.get("version", ""),
            name=info_dict.get("name", "ephemeral"),
            algorithm=info_dict.get("algorithm", "ed25519"),
        )
        return instance

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_from_config(self, config_path: str) -> None:
        if not os.path.exists(config_path):
            raise ConfigError(
                f"Config file not found: {config_path}\n"
                "Run 'jacs create' or call jacs.create() to create a new agent."
            )

        self._agent.load(config_path)

        with open(config_path, "r") as f:
            config = json.load(f)

        id_ver = config.get("jacs_agent_id_and_version", "")
        parts = id_ver.split(":") if id_ver else ["", ""]
        agent_id = parts[0] if parts else ""
        version = parts[1] if len(parts) > 1 else ""
        key_dir = config.get("jacs_key_directory", "./jacs_keys")

        self._agent_info = AgentInfo(
            agent_id=agent_id,
            version=version,
            name=config.get("name"),
            algorithm=config.get("jacs_agent_key_algorithm", "RSA"),
            config_path=config_path,
            public_key_path=os.path.join(key_dir, "jacs.public.pem"),
        )

    def _require_agent(self):
        if self._agent is None:
            raise AgentNotLoadedError("No agent loaded on this JacsClient instance.")
        return self._agent

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def agent_id(self) -> str:
        if self._agent_info is None:
            raise AgentNotLoadedError("No agent loaded.")
        return self._agent_info.agent_id

    @property
    def name(self) -> Optional[str]:
        if self._agent_info is None:
            raise AgentNotLoadedError("No agent loaded.")
        return self._agent_info.name

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "JacsClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.reset()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Clear internal state. After calling reset() the client is
        no longer usable until re-initialised."""
        self._agent = None  # type: ignore[assignment]
        self._agent_info = None

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign_message(self, data: Any) -> SignedDocument:
        """Sign arbitrary data and return a SignedDocument."""
        agent = self._require_agent()
        try:
            doc_json = json.dumps(
                {"jacsDocument": {"type": "message", "content": data}}
            )
            result = agent.create_document(
                document_string=doc_json,
                custom_schema=None,
                outputfilename=None,
                no_save=True,
                attachments=None,
                embed=None,
            )
            return _parse_signed_document(result)
        except Exception as e:
            raise SigningError(f"Failed to sign message: {e}")

    def sign_file(self, path: str, embed: bool = False) -> SignedDocument:
        """Sign a file with optional content embedding."""
        agent = self._require_agent()
        if not os.path.exists(path):
            raise JacsError(f"File not found: {path}")
        try:
            doc_json = json.dumps(
                {
                    "jacsDocument": {
                        "type": "file",
                        "filename": os.path.basename(path),
                    }
                }
            )
            result = agent.create_document(
                document_string=doc_json,
                custom_schema=None,
                outputfilename=None,
                no_save=True,
                attachments=path,
                embed=embed,
            )
            return _parse_signed_document(result)
        except Exception as e:
            raise SigningError(f"Failed to sign file: {e}")

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, document: Union[str, dict, SignedDocument]) -> VerificationResult:
        """Verify a signed JACS document."""
        agent = self._require_agent()
        if isinstance(document, SignedDocument):
            doc_str = document.raw_json
        elif isinstance(document, dict):
            doc_str = json.dumps(document)
        else:
            doc_str = document

        try:
            is_valid = agent.verify_document(doc_str)
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
            if self._strict:
                raise VerificationError(f"Verification failed (strict mode): {e}") from e
            return VerificationResult(valid=False, errors=[str(e)])

    def verify_self(self) -> VerificationResult:
        """Verify this client's agent integrity."""
        agent = self._require_agent()
        try:
            agent.verify_agent(None)
            return VerificationResult(
                valid=True,
                signer_id=self._agent_info.agent_id if self._agent_info else "",
                content_hash_valid=True,
                signature_valid=True,
            )
        except Exception as e:
            if self._strict:
                raise VerificationError(f"Self-verification failed (strict mode): {e}") from e
            return VerificationResult(valid=False, errors=[str(e)])

    def verify_by_id(self, doc_id: str) -> VerificationResult:
        """Verify a document by its storage ID (uuid:version format)."""
        agent = self._require_agent()
        if ":" not in doc_id:
            raise JacsError(
                f"Document ID must be in 'uuid:version' format, got '{doc_id}'."
            )
        try:
            is_valid = agent.verify_document_by_id(doc_id)
            return VerificationResult(
                valid=is_valid,
                signer_id=self._agent_info.agent_id if self._agent_info else "",
                content_hash_valid=is_valid,
                signature_valid=is_valid,
            )
        except Exception as e:
            if self._strict:
                raise VerificationError(f"Verification failed (strict mode): {e}") from e
            return VerificationResult(valid=False, errors=[str(e)])

    # ------------------------------------------------------------------
    # Agreements
    # ------------------------------------------------------------------

    def create_agreement(
        self,
        document: Union[str, dict, SignedDocument],
        agent_ids: List[str],
        question: Optional[str] = None,
        context: Optional[str] = None,
        field_name: Optional[str] = None,
        timeout: Optional[str] = None,
        quorum: Optional[int] = None,
        required_algorithms: Optional[List[str]] = None,
        minimum_strength: Optional[str] = None,
    ) -> SignedDocument:
        """Create a multi-party agreement.

        Args:
            document: The document to create an agreement on
            agent_ids: List of agent IDs required to sign
            question: Optional purpose of the agreement
            context: Optional additional context
            field_name: Optional custom agreement field name
            timeout: Optional ISO 8601 deadline
            quorum: Optional minimum signatures required (M-of-N)
            required_algorithms: Optional list of accepted algorithms
            minimum_strength: Optional "classical" or "post-quantum"
        """
        agent = self._require_agent()
        if isinstance(document, SignedDocument):
            doc_str = document.raw_json
        elif isinstance(document, dict):
            doc_str = json.dumps(document)
        else:
            doc_str = document

        has_options = any(
            x is not None
            for x in (timeout, quorum, required_algorithms, minimum_strength)
        )

        try:
            if has_options:
                result = agent.create_agreement_with_options(
                    doc_str,
                    agent_ids,
                    question=question,
                    context=context,
                    agreement_fieldname=field_name,
                    timeout=timeout,
                    quorum=quorum,
                    required_algorithms=required_algorithms,
                    minimum_strength=minimum_strength,
                )
            else:
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
        self,
        document: Union[str, dict, SignedDocument],
        agreement_fieldname: Optional[str] = None,
    ) -> SignedDocument:
        """Sign an existing agreement as this client's agent."""
        agent = self._require_agent()
        if isinstance(document, SignedDocument):
            doc_str = document.raw_json
        elif isinstance(document, dict):
            doc_str = json.dumps(document)
        else:
            doc_str = document

        try:
            result = agent.sign_agreement(doc_str, agreement_fieldname)
            return _parse_signed_document(result)
        except Exception as e:
            raise JacsError(f"Failed to sign agreement: {e}")

    def check_agreement(
        self,
        document: Union[str, dict, SignedDocument],
        agreement_fieldname: Optional[str] = None,
    ) -> AgreementStatus:
        """Check the status of a multi-party agreement."""
        agent = self._require_agent()
        if isinstance(document, SignedDocument):
            doc_str = document.raw_json
        elif isinstance(document, dict):
            doc_str = json.dumps(document)
        else:
            doc_str = document

        try:
            result_json = agent.check_agreement(doc_str, agreement_fieldname)
            result_data = json.loads(result_json)
            signers = [
                SignerStatus.from_dict(s) for s in result_data.get("signers", [])
            ]
            return AgreementStatus(
                complete=result_data.get("complete", False),
                signers=signers,
                pending=result_data.get("pending", []),
            )
        except json.JSONDecodeError as e:
            raise JacsError(f"Invalid agreement status response: {e}")
        except Exception as e:
            raise JacsError(f"Failed to check agreement: {e}")

    # ------------------------------------------------------------------
    # Trust store
    # ------------------------------------------------------------------

    def trust_agent(self, agent_json: str) -> str:
        return _trust_agent(agent_json)

    def list_trusted_agents(self) -> List[str]:
        return _list_trusted_agents()

    def untrust_agent(self, agent_id: str) -> None:
        _untrust_agent(agent_id)

    def is_trusted(self, agent_id: str) -> bool:
        return _is_trusted(agent_id)

    def get_trusted_agent(self, agent_id: str) -> str:
        return _get_trusted_agent(agent_id)

    # ------------------------------------------------------------------
    # Agent management
    # ------------------------------------------------------------------

    def update_agent(self, data: Union[str, dict]) -> str:
        """Update the agent document with new data and re-sign it."""
        agent = self._require_agent()
        data_string = json.dumps(data) if isinstance(data, dict) else data
        try:
            return agent.update_agent(data_string)
        except Exception as e:
            raise JacsError(f"Failed to update agent: {e}")

    def update_document(
        self,
        doc_id: str,
        data: Union[str, dict],
        attachments: Optional[List[str]] = None,
        embed: bool = False,
    ) -> SignedDocument:
        """Update an existing document with new data and re-sign it."""
        agent = self._require_agent()
        data_string = json.dumps(data) if isinstance(data, dict) else data
        try:
            result = agent.update_document(doc_id, data_string, attachments, embed)
            return _parse_signed_document(result)
        except Exception as e:
            raise JacsError(f"Failed to update document: {e}")

    def export_agent(self) -> str:
        """Export the agent document JSON for sharing."""
        agent = self._require_agent()
        try:
            return agent.get_agent_json()
        except Exception as e:
            raise JacsError(f"Failed to export agent: {e}")

    def audit(
        self,
        config_path: Optional[str] = None,
        recent_n: Optional[int] = None,
    ) -> dict:
        """Run a read-only security audit."""
        try:
            json_str = _audit(config_path=config_path, recent_n=recent_n)
            return json.loads(json_str)
        except Exception as e:
            raise JacsError(f"Audit failed: {e}")

    # ------------------------------------------------------------------
    # A2A helpers
    # ------------------------------------------------------------------

    def get_a2a(
        self,
        url: Optional[str] = None,
        skills: Optional[List[dict]] = None,
    ) -> "JACSA2AIntegration":
        """Return a :class:`JACSA2AIntegration` wired to this client.

        Args:
            url: Base URL for the agent's A2A endpoint.  Stored on the
                returned integration object as ``default_url`` for
                convenience but not required.
            skills: Optional pre-built skill dicts to attach when
                exporting an agent card.

        Returns:
            A :class:`JACSA2AIntegration` instance backed by this client.
        """
        from .a2a import JACSA2AIntegration

        integration = JACSA2AIntegration(self)
        integration.default_url = url  # type: ignore[attr-defined]
        integration.default_skills = skills  # type: ignore[attr-defined]
        return integration

    def export_agent_card(
        self,
        url: Optional[str] = None,
        skills: Optional[List[dict]] = None,
    ) -> "A2AAgentCard":
        """Export this client's agent as an A2A Agent Card.

        This is a convenience shorthand for::

            a2a = client.get_a2a()
            card = a2a.export_agent_card(agent_data)

        It builds ``agent_data`` from the client's own agent JSON and
        delegates to :meth:`JACSA2AIntegration.export_agent_card`.

        Args:
            url: Base URL for the agent's A2A endpoint.  If provided it
                is injected as ``jacsAgentDomain`` so the card's
                ``supportedInterfaces`` points to a real endpoint instead
                of the placeholder ``agent-<id>.example.com``.
            skills: Optional list of raw JACS service dicts.  When
                supplied they are injected as ``jacsServices`` in the
                agent data fed to the card builder.

        Returns:
            An :class:`A2AAgentCard` dataclass.
        """
        from .a2a import JACSA2AIntegration

        agent = self._require_agent()
        try:
            agent_json_str = agent.get_agent_json()
            agent_data = json.loads(agent_json_str)
        except Exception as e:
            raise JacsError(f"Failed to export agent card: {e}")

        if url:
            agent_data["jacsAgentDomain"] = url
        if skills:
            agent_data["jacsServices"] = skills

        integration = JACSA2AIntegration(self)
        return integration.export_agent_card(agent_data)

    def sign_artifact(
        self,
        artifact: dict,
        artifact_type: str,
        parent_signatures: Optional[List[dict]] = None,
    ) -> dict:
        """Sign an A2A artifact with JACS provenance.

        Convenience shorthand for::

            a2a = client.get_a2a()
            a2a.sign_artifact(artifact, artifact_type, parent_signatures)

        Args:
            artifact: The A2A artifact dict to wrap and sign.
            artifact_type: Type label (e.g. ``"task"``, ``"message"``).
            parent_signatures: Optional parent signatures for chain of
                custody.

        Returns:
            The signed, JACS-wrapped artifact dict.
        """
        from .a2a import JACSA2AIntegration

        integration = JACSA2AIntegration(self)
        return integration.sign_artifact(artifact, artifact_type, parent_signatures)


__all__ = ["JacsClient"]
