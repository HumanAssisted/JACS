"""
A2A (Agent-to-Agent) Protocol Integration for JACS Python

This module provides Python bindings for JACS's A2A protocol integration,
enabling JACS agents to participate in the Agent-to-Agent communication protocol.

Implements A2A protocol v0.4.0 (September 2025).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import warnings
from typing import Dict, List, Optional, Any, TYPE_CHECKING, Set
from dataclasses import dataclass, field
import base64
import uuid
from datetime import datetime

logger = logging.getLogger("jacs.a2a")

if TYPE_CHECKING:
    from .client import JacsClient


# ---------------------------------------------------------------------------
# A2A v0.4.0 Data Types
# ---------------------------------------------------------------------------

@dataclass
class A2AAgentInterface:
    """A2A Agent Interface — declares a reachable endpoint with its protocol binding."""
    url: str
    protocol_binding: str  # "jsonrpc", "grpc", "rest"
    tenant: Optional[str] = None


@dataclass
class A2AAgentProvider:
    """A2A Agent Provider info."""
    url: Optional[str] = None
    organization: Optional[str] = None


@dataclass
class A2AAgentSkill:
    """A2A Agent Skill (v0.4.0)"""
    id: str
    name: str
    description: str
    tags: List[str]
    examples: Optional[List[str]] = None
    input_modes: Optional[List[str]] = None
    output_modes: Optional[List[str]] = None
    security: Optional[List[Any]] = None


@dataclass
class A2AAgentExtension:
    """A2A Agent Extension declaration (v0.4.0)"""
    uri: str
    description: Optional[str] = None
    required: Optional[bool] = None


@dataclass
class A2AAgentCapabilities:
    """A2A Agent Capabilities (v0.4.0)"""
    streaming: Optional[bool] = None
    push_notifications: Optional[bool] = None
    extended_agent_card: Optional[bool] = None
    extensions: Optional[List[A2AAgentExtension]] = None


@dataclass
class A2AAgentCardSignature:
    """JWS signature embedded in an AgentCard (v0.4.0)"""
    jws: str
    key_id: Optional[str] = None


@dataclass
class A2AAgentCard:
    """A2A Agent Card (v0.4.0)

    Published at /.well-known/agent-card.json for zero-config discovery.
    """
    # Required fields
    name: str
    description: str
    version: str
    protocol_versions: List[str]
    supported_interfaces: List[A2AAgentInterface]
    default_input_modes: List[str]
    default_output_modes: List[str]
    capabilities: A2AAgentCapabilities
    skills: List[A2AAgentSkill]
    # Optional fields
    provider: Optional[A2AAgentProvider] = None
    documentation_url: Optional[str] = None
    icon_url: Optional[str] = None
    security_schemes: Optional[Dict[str, Dict[str, Any]]] = None
    security: Optional[List[Any]] = None
    signatures: Optional[List[A2AAgentCardSignature]] = None
    metadata: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Integration Class
# ---------------------------------------------------------------------------

def _sha256_hex(data: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _build_trust_block(trust_assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Map canonical trustAssessment data to the wrapper's legacy trust block."""
    return {
        "allowed": bool(trust_assessment.get("allowed", False)),
        "jacs_registered": bool(trust_assessment.get("jacsRegistered", False)),
        "trust_level": _legacy_trust_level(trust_assessment.get("trustLevel")),
        "reason": trust_assessment.get("reason", ""),
        "policy": trust_assessment.get("policy"),
    }


def _deprecation_warn(old_name: str, new_name: str) -> None:
    """Emit a DeprecationWarning for a renamed method, if enabled.

    Warnings are only emitted when the ``JACS_SHOW_DEPRECATIONS``
    environment variable is set to a truthy value.
    """
    if os.environ.get("JACS_SHOW_DEPRECATIONS"):
        warnings.warn(
            f"{old_name}() is deprecated, use {new_name}() instead",
            DeprecationWarning,
            stacklevel=3,  # caller -> wrapper -> this helper
        )


_POLICY_NAMES = {
    "open": "Open",
    "verified": "Verified",
    "strict": "Strict",
}

_CANONICAL_TRUST_LEVELS = {
    "explicitly_trusted": "ExplicitlyTrusted",
    "trusted": "ExplicitlyTrusted",
    "explicitlytrusted": "ExplicitlyTrusted",
    "jacs_verified": "JacsVerified",
    "jacsverified": "JacsVerified",
    "jacs_registered": "JacsVerified",
    "untrusted": "Untrusted",
}

_LEGACY_TRUST_LEVELS = {
    "ExplicitlyTrusted": "trusted",
    "JacsVerified": "jacs_registered",
    "Untrusted": "untrusted",
}

_RESULT_ALIASES = {
    "signer_id": "signerId",
    "signer_version": "signerVersion",
    "artifact_type": "artifactType",
    "original_artifact": "originalArtifact",
    "parent_verification_results": "parentVerificationResults",
    "parent_signatures_valid": "parentSignaturesValid",
}


def _canonical_policy_name(policy: Optional[str]) -> Optional[str]:
    if policy is None:
        return None
    return _POLICY_NAMES.get(str(policy).lower(), str(policy))


def _canonical_trust_level(level: Any) -> str:
    if level is None:
        return "Untrusted"
    return _CANONICAL_TRUST_LEVELS.get(str(level), _CANONICAL_TRUST_LEVELS.get(str(level).lower(), "Untrusted"))


def _legacy_trust_level(level: Any) -> str:
    return _LEGACY_TRUST_LEVELS.get(_canonical_trust_level(level), "untrusted")


def _is_unconfigured_mock(value: Any) -> bool:
    return type(value).__module__.startswith("unittest.mock")


def _get_configured_callable(obj: Any, name: str) -> Any:
    method = getattr(obj, name, None)
    if not callable(method):
        return None
    if _is_unconfigured_mock(method):
        side_effect = getattr(method, "side_effect", None)
        return_value = getattr(method, "return_value", None)
        if side_effect is None and _is_unconfigured_mock(return_value):
            return None
    return method


def _has_jacs_extension(card: Dict[str, Any]) -> bool:
    capabilities = card.get("capabilities")
    if not isinstance(capabilities, dict):
        return False
    extensions = capabilities.get("extensions")
    if not isinstance(extensions, list):
        return False
    return any(
        isinstance(extension, dict)
        and extension.get("uri") == JACSA2AIntegration.JACS_EXTENSION_URI
        for extension in extensions
    )


def _build_synthetic_agent_card(wrapped_artifact: Dict[str, Any]) -> Dict[str, Any]:
    signature = wrapped_artifact.get("jacsSignature")
    signer_id = signature.get("agentID") if isinstance(signature, dict) else None
    card: Dict[str, Any] = {
        "name": signer_id or "unknown",
        "capabilities": {},
        "metadata": {"jacsId": signer_id},
    }
    if str(wrapped_artifact.get("jacsType", "")).startswith("a2a-"):
        card["capabilities"]["extensions"] = [{"uri": JACSA2AIntegration.JACS_EXTENSION_URI}]
    return card


def _build_trust_assessment(
    client: "JacsClient",
    policy: str,
    agent_card: Dict[str, Any],
) -> Dict[str, Any]:
    metadata = agent_card.get("metadata")
    agent_id = metadata.get("jacsId") if isinstance(metadata, dict) else None
    jacs_registered = _has_jacs_extension(agent_card)
    trusted = False
    is_trusted = _get_configured_callable(client, "is_trusted")
    if callable(is_trusted) and agent_id:
        try:
            trusted = bool(is_trusted(agent_id))
        except Exception:
            trusted = False

    trust_level = "ExplicitlyTrusted" if trusted else "JacsVerified" if jacs_registered else "Untrusted"
    normalized_policy = str(policy).lower()
    policy_name = _canonical_policy_name(normalized_policy) or "Verified"

    if normalized_policy == "open":
        allowed = True
        reason = "Open policy: all agents are allowed"
    elif normalized_policy == "verified":
        allowed = jacs_registered
        reason = (
            "Verified policy: agent has JACS provenance extension"
            if jacs_registered
            else "Verified policy: agent does not declare JACS provenance extension"
        )
    else:
        allowed = trusted
        if trusted:
            reason = f"Strict policy: agent '{agent_id}' is in the local trust store."
        elif agent_id:
            reason = (
                f"Strict policy: agent '{agent_id}' is not in the local trust store. "
                "Use trust_agent() to add it first."
            )
        else:
            reason = "Strict policy: remote agent is missing a jacsId and cannot be trusted."

    return {
        "allowed": allowed,
        "trustLevel": trust_level,
        "reason": reason,
        "jacsRegistered": jacs_registered,
        "agentId": agent_id,
        "policy": policy_name,
    }


def _normalize_status(status: Any, *, valid: bool, reason: str = "") -> Any:
    if isinstance(status, str) and status in {"Verified", "SelfSigned"}:
        return status
    if isinstance(status, dict):
        if "Unverified" in status and isinstance(status["Unverified"], dict):
            return {"Unverified": {"reason": str(status["Unverified"].get("reason", reason))}}
        if "Invalid" in status and isinstance(status["Invalid"], dict):
            return {"Invalid": {"reason": str(status["Invalid"].get("reason", reason))}}
    if isinstance(status, str):
        if status == "Unverified":
            return {"Unverified": {"reason": reason or "verification could not be completed"}}
        if status == "Invalid":
            return {"Invalid": {"reason": reason or "signature verification failed"}}
    if valid:
        return "Verified"
    return {"Invalid": {"reason": reason or "signature verification failed"}}


def _normalize_parent_result(parent: Dict[str, Any]) -> Dict[str, Any]:
    verified = bool(parent.get("verified", parent.get("valid", False)))
    return {
        "index": int(parent.get("index", 0)),
        "artifactId": str(parent.get("artifactId", "")),
        "signerId": str(parent.get("signerId", "")),
        "status": _normalize_status(parent.get("status"), valid=verified),
        "verified": verified,
    }


def _canonical_result_from_wrapped_artifact(
    wrapped_artifact: Dict[str, Any],
    *,
    valid: bool,
    status: Any,
    parent_results: Optional[List[Dict[str, Any]]] = None,
    trust_assessment: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    signature = wrapped_artifact.get("jacsSignature")
    signer_id = signature.get("agentID", "") if isinstance(signature, dict) else ""
    signer_version = signature.get("agentVersion", "") if isinstance(signature, dict) else ""
    normalized_parent_results = [
        _normalize_parent_result(parent_result)
        for parent_result in (parent_results or [])
    ]

    result: Dict[str, Any] = {
        "status": _normalize_status(status, valid=valid),
        "valid": valid,
        "signerId": signer_id,
        "signerVersion": signer_version,
        "artifactType": str(wrapped_artifact.get("jacsType", "")),
        "timestamp": str(wrapped_artifact.get("jacsVersionDate", "")),
        "parentSignaturesValid": all(parent["verified"] for parent in normalized_parent_results),
        "parentVerificationResults": normalized_parent_results,
        "originalArtifact": wrapped_artifact.get("a2aArtifact", {}),
    }
    if trust_assessment:
        normalized_trust = {
            "allowed": bool(trust_assessment.get("allowed", False)),
            "trustLevel": _canonical_trust_level(trust_assessment.get("trustLevel")),
            "reason": str(trust_assessment.get("reason", "")),
            "jacsRegistered": bool(trust_assessment.get("jacsRegistered", False)),
            "agentId": trust_assessment.get("agentId"),
            "policy": _canonical_policy_name(trust_assessment.get("policy")) or "Verified",
        }
        result["trustLevel"] = normalized_trust["trustLevel"]
        result["trustAssessment"] = normalized_trust
    return result


class _A2AVerificationResult(dict):
    """Canonical result with legacy field aliases available through accessors."""

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return dict.__contains__(self, key)
        if dict.__contains__(self, key):
            return True
        if key in _RESULT_ALIASES:
            return dict.__contains__(self, _RESULT_ALIASES[key])
        if key == "parent_signatures_count":
            return dict.__contains__(self, "parentVerificationResults")
        if key == "trust":
            return dict.__contains__(self, "trustAssessment")
        return False

    def __getitem__(self, key: str) -> Any:
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        if key in _RESULT_ALIASES:
            return dict.__getitem__(self, _RESULT_ALIASES[key])
        if key == "parent_signatures_count":
            return len(dict.get(self, "parentVerificationResults", []))
        if key == "trust":
            trust_assessment = dict.get(self, "trustAssessment")
            if trust_assessment is None:
                raise KeyError(key)
            return _build_trust_block(trust_assessment)
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


class JACSA2AIntegration:
    """JACS integration with A2A protocol (v0.4.0)"""

    A2A_PROTOCOL_VERSION = "0.4.0"
    JACS_EXTENSION_URI = "urn:jacs:provenance-v1"

    # Algorithms actually supported by the JACS cryptographic stack.
    SUPPORTED_ALGORITHMS = ["ring-Ed25519", "RSA-PSS", "pq2025"]

    VALID_TRUST_POLICIES = ("open", "verified", "strict")

    def __init__(
        self,
        client: "JacsClient",
        trust_policy: str = "verified",
    ) -> None:
        """Initialize JACS A2A integration.

        Args:
            client: A ``JacsClient`` instance that provides signing
                and verification capabilities.
            trust_policy: Default trust policy applied when assessing
                remote agents. One of ``"open"``, ``"verified"``
                (default), or ``"strict"``.
        """
        if trust_policy not in self.VALID_TRUST_POLICIES:
            raise ValueError(
                f"Invalid trust_policy: {trust_policy!r}. "
                f"Must be one of {self.VALID_TRUST_POLICIES}."
            )
        self.client = client
        self.trust_policy = trust_policy

    @classmethod
    def from_config(cls, config_path: str) -> "JACSA2AIntegration":
        """Create an integration instance from a JACS config file.

        This is a convenience factory for callers that do not yet have
        a ``JacsClient`` instance.

        Args:
            config_path: Path to the JACS configuration file.

        Returns:
            A new ``JACSA2AIntegration`` wired to a freshly-created client.
        """
        from .client import JacsClient

        client = JacsClient(config_path=config_path)
        return cls(client)

    @classmethod
    def quickstart(
        cls,
        name: str = "jacs-agent",
        domain: str = "localhost",
        description: Optional[str] = None,
        algorithm: Optional[str] = None,
        config_path: Optional[str] = None,
        url: Optional[str] = None,
    ) -> "JACSA2AIntegration":
        """One-liner to create a ready-to-use A2A integration.

        Creates (or loads) a persistent JACS agent via
        ``JacsClient.quickstart(name=..., domain=...)`` and wires it into a new
        ``JACSA2AIntegration``.

        Example::

            a2a = JACSA2AIntegration.quickstart(name="a2a-agent", domain="a2a.local")
            card = a2a.export_agent_card(agent_data)

        Args:
            name: Agent name for first-time quickstart creation.
            domain: Agent domain for DNS/public-key verification workflows.
            description: Optional human-readable agent description.
            algorithm: Signing algorithm (default ``"pq2025"``).
            config_path: Path to the JACS config file.
                Defaults to ``"./jacs.config.json"``.
            url: Default base URL stored on the integration.
        """
        from .client import JacsClient

        client = JacsClient.quickstart(
            name=name,
            domain=domain,
            description=description,
            algorithm=algorithm,
            config_path=config_path,
        )
        integration = cls(client)
        integration.default_url = url  # type: ignore[attr-defined]
        return integration

    def serve(self, port: int = 8000, host: str = "0.0.0.0") -> None:
        """Start a minimal HTTP server that publishes the agent card.

        Serves all five ``/.well-known/`` endpoints required for A2A
        agent discovery.

        Requires ``uvicorn`` and ``fastapi`` (install with
        ``pip install jacs[a2a-server]``).

        This is a blocking call intended for quick demos and local
        development.  For production use, use
        :func:`jacs.a2a_server.jacs_a2a_routes` and mount the router
        into your own ASGI application.

        Args:
            port: TCP port to listen on (default 8000).
            host: Bind address (default ``"0.0.0.0"``).
        """
        from .a2a_server import serve_a2a

        url = getattr(self, "default_url", None)
        if url:
            # Inject domain into agent data before building routes.
            try:
                agent_json_str = self.client._agent.get_agent_json()
                agent_data = json.loads(agent_json_str)
                agent_data["jacsAgentDomain"] = url
                # Temporarily patch the agent's response for route building.
                _orig = self.client._agent.get_agent_json
                self.client._agent.get_agent_json = lambda: json.dumps(agent_data)
                try:
                    serve_a2a(self.client, port=port, host=host)
                finally:
                    self.client._agent.get_agent_json = _orig
                return
            except Exception:
                pass  # Fall through to default

        serve_a2a(self.client, port=port, host=host)

    def export_agent_card(self, agent_data: Dict[str, Any]) -> A2AAgentCard:
        """Export a JACS agent as an A2A Agent Card (v0.4.0)

        Args:
            agent_data: JACS agent data dictionary

        Returns:
            A2AAgentCard object
        """
        agent_id = agent_data.get("jacsId", "unknown")
        agent_name = agent_data.get("jacsName", "Unnamed JACS Agent")
        agent_description = agent_data.get("jacsDescription", "JACS-enabled agent")
        agent_version = agent_data.get("jacsVersion", "1")

        # Build supported interfaces from jacsAgentDomain or agent ID
        domain = agent_data.get("jacsAgentDomain")
        if domain:
            base_url = f"https://{domain}/agent/{agent_id}"
        else:
            base_url = f"https://agent-{agent_id}.example.com"

        supported_interfaces = [
            A2AAgentInterface(
                url=base_url,
                protocol_binding="jsonrpc",
            )
        ]

        # Convert JACS services to A2A skills
        skills = self._convert_services_to_skills(agent_data.get("jacsServices", []))

        # Define security schemes as a keyed map
        security_schemes = {
            "bearer-jwt": {
                "type": "http",
                "scheme": "Bearer",
                "bearerFormat": "JWT",
            },
            "api-key": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
            },
        }

        # Create JACS extension
        jacs_extension = A2AAgentExtension(
            uri=self.JACS_EXTENSION_URI,
            description="JACS cryptographic document signing and verification",
            required=False,
        )

        capabilities = A2AAgentCapabilities(extensions=[jacs_extension])

        # Create metadata
        metadata = {
            "jacsAgentType": agent_data.get("jacsAgentType"),
            "jacsId": agent_id,
            "jacsVersion": agent_data.get("jacsVersion"),
        }

        return A2AAgentCard(
            name=agent_name,
            description=agent_description,
            version=str(agent_version),
            protocol_versions=[self.A2A_PROTOCOL_VERSION],
            supported_interfaces=supported_interfaces,
            default_input_modes=["text/plain", "application/json"],
            default_output_modes=["text/plain", "application/json"],
            capabilities=capabilities,
            skills=skills,
            security_schemes=security_schemes,
            metadata=metadata,
        )

    def _convert_services_to_skills(self, services: List[Dict[str, Any]]) -> List[A2AAgentSkill]:
        """Convert JACS services to A2A skills (v0.4.0)"""
        skills = []

        for service in services:
            service_name = service.get("name", service.get("serviceDescription", "unnamed_service"))
            service_desc = service.get("serviceDescription", "No description")

            tools = service.get("tools", [])
            if tools:
                for tool in tools:
                    if function := tool.get("function"):
                        fn_name = function.get("name", service_name)
                        fn_desc = function.get("description", service_desc)

                        skill = A2AAgentSkill(
                            id=self._slugify(fn_name),
                            name=fn_name,
                            description=fn_desc,
                            tags=self._derive_tags(service_name, fn_name),
                        )
                        skills.append(skill)
            else:
                skill = A2AAgentSkill(
                    id=self._slugify(service_name),
                    name=service_name,
                    description=service_desc,
                    tags=self._derive_tags(service_name, service_name),
                )
                skills.append(skill)

        # Add default verification skill if none exist
        if not skills:
            skills.append(A2AAgentSkill(
                id="verify-signature",
                name="verify_signature",
                description="Verify JACS document signatures",
                tags=["jacs", "verification", "cryptography"],
                examples=[
                    "Verify a signed JACS document",
                    "Check document signature integrity",
                ],
                input_modes=["application/json"],
                output_modes=["application/json"],
            ))

        return skills

    def create_extension_descriptor(self) -> Dict[str, Any]:
        """Create JACS extension descriptor for A2A"""
        return {
            "uri": self.JACS_EXTENSION_URI,
            "name": "JACS Document Provenance",
            "version": "1.0",
            "a2aProtocolVersion": self.A2A_PROTOCOL_VERSION,
            "description": "Provides cryptographic document signing and verification with post-quantum support",
            "specification": "https://jacs.ai/specs/a2a-extension",
            "capabilities": {
                "documentSigning": {
                    "description": "Sign documents with JACS signatures",
                    "algorithms": self.SUPPORTED_ALGORITHMS,
                    "formats": ["jacs-v1", "jws-detached"]
                },
                "documentVerification": {
                    "description": "Verify JACS signatures on documents",
                    "offlineCapable": True,
                    "chainOfCustody": True
                },
                "postQuantumCrypto": {
                    "description": "Support for quantum-resistant signatures",
                    "algorithms": [
                        a for a in self.SUPPORTED_ALGORITHMS
                        if a.startswith("pq")
                    ]
                }
            },
            "endpoints": {
                "sign": {
                    "path": "/jacs/sign",
                    "method": "POST",
                    "description": "Sign a document with JACS"
                },
                "verify": {
                    "path": "/jacs/verify",
                    "method": "POST",
                    "description": "Verify a JACS signature"
                },
                "publicKey": {
                    "path": "/.well-known/jacs-pubkey.json",
                    "method": "GET",
                    "description": "Retrieve agent's public key"
                }
            }
        }

    def sign_artifact(
        self,
        artifact: Dict[str, Any],
        artifact_type: str,
        parent_signatures: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Sign an A2A artifact with JACS provenance.

        Args:
            artifact: The A2A artifact to wrap and sign.
            artifact_type: Type of artifact (e.g., ``"task"``, ``"message"``).
            parent_signatures: Optional parent signatures for chain of custody.

        Returns:
            JACS-wrapped artifact with cryptographic signature.
        """
        wrapped = {
            "jacsId": str(uuid.uuid4()),
            "jacsVersion": str(uuid.uuid4()),
            "jacsType": f"a2a-{artifact_type}",
            "jacsLevel": "artifact",
            "jacsVersionDate": datetime.utcnow().isoformat() + "Z",
            "$schema": "https://jacs.ai/schemas/header/v1/header.schema.json",
            "a2aArtifact": artifact
        }

        if parent_signatures:
            wrapped["jacsParentSignatures"] = parent_signatures

        signed_json = self.client._agent.sign_request(wrapped)
        return json.loads(signed_json)

    def wrap_artifact_with_provenance(
        self,
        artifact: Dict[str, Any],
        artifact_type: str,
        parent_signatures: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Wrap an A2A artifact with JACS provenance signature.

        .. deprecated:: 0.9.0
            Use :meth:`sign_artifact` instead.

        Args:
            artifact: The A2A artifact to wrap.
            artifact_type: Type of artifact (e.g., ``"task"``, ``"message"``).
            parent_signatures: Optional parent signatures for chain of custody.

        Returns:
            JACS-wrapped artifact with signature.
        """
        _deprecation_warn("wrap_artifact_with_provenance", "sign_artifact")
        return self.sign_artifact(artifact, artifact_type, parent_signatures)

    # ------------------------------------------------------------------
    # Trust policy API
    # ------------------------------------------------------------------

    def assess_remote_agent(
        self,
        agent_card_json: str,
        policy: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Assess trust for a remote A2A agent card.

        Applies a trust policy against a raw Agent Card JSON string.
        Reuses the same policy logic as
        :func:`jacs.a2a_discovery.discover_and_assess`.

        Args:
            agent_card_json: JSON string of the remote Agent Card.
            policy: Trust policy to apply. If ``None``, uses the
                instance's ``trust_policy`` (default ``"verified"``).

        Returns:
            A dict with::

                {
                    "card": <parsed card dict>,
                    "jacs_registered": bool,
                    "trust_level": "untrusted" | "jacs_registered" | "trusted",
                    "allowed": bool,
                }

        Raises:
            ValueError: If *policy* is not a valid value.
        """
        effective_policy = policy or self.trust_policy
        if effective_policy not in self.VALID_TRUST_POLICIES:
            raise ValueError(
                f"Invalid trust policy: {effective_policy!r}. "
                f"Must be one of {self.VALID_TRUST_POLICIES}."
            )
        card = json.loads(agent_card_json)
        assess_a2a_agent = _get_configured_callable(self.client._agent, "assess_a2a_agent")
        if assess_a2a_agent is not None:
            canonical_json = assess_a2a_agent(agent_card_json, effective_policy)
            canonical = json.loads(canonical_json)
        else:
            canonical = _build_trust_assessment(self.client, effective_policy, card)

        return {
            "card": card,
            "jacs_registered": bool(canonical.get("jacsRegistered", False)),
            "trust_level": _legacy_trust_level(canonical.get("trustLevel")),
            "allowed": bool(canonical.get("allowed", False)),
            "reason": canonical.get("reason", ""),
            "policy": canonical.get("policy", _canonical_policy_name(effective_policy)),
        }

    def trust_a2a_agent(self, agent_card_json: str) -> str:
        """Add a remote A2A agent to the local trust store.

        Extracts the agent document from the card's metadata and
        delegates to :meth:`JacsClient.trust_agent`.

        Args:
            agent_card_json: JSON string of the remote Agent Card.

        Returns:
            Result string from the trust store operation.

        Raises:
            ValueError: If the card has no ``jacsId`` in metadata.
        """
        from .a2a_discovery import _extract_agent_id

        card = json.loads(agent_card_json)
        agent_id = _extract_agent_id(card)
        if not agent_id:
            raise ValueError(
                "Cannot trust agent: card has no jacsId in metadata."
            )

        # Build a minimal agent document for the trust store.
        # The trust store needs the full agent JSON, but an Agent Card
        # only carries metadata.  We pass the card as-is — the trust
        # store will index it by jacsId.
        return self.client.trust_agent(agent_card_json)

    def verify_wrapped_artifact(
        self,
        wrapped_artifact: Dict[str, Any],
        assess_trust: bool = False,
        trust_policy: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify a JACS-wrapped A2A artifact.

        Args:
            wrapped_artifact: The wrapped artifact to verify.
            assess_trust: If ``True``, include a trust assessment of the
                signer in the result.  Requires that the artifact's
                signer published an Agent Card with JACS metadata.
            trust_policy: Policy for the trust assessment.  Defaults to
                the instance's ``trust_policy``.

        Returns:
            Verification result dictionary.  When ``assess_trust`` is
            ``True``, includes an extra ``trust`` key with the
            assessment result.
        """
        effective_policy = (trust_policy or self.trust_policy) if assess_trust else None
        if effective_policy and effective_policy not in self.VALID_TRUST_POLICIES:
            raise ValueError(
                f"Invalid trust policy: {effective_policy!r}. "
                f"Must be one of {self.VALID_TRUST_POLICIES}."
            )
        synthetic_card = _build_synthetic_agent_card(wrapped_artifact) if assess_trust else None
        return self._verify_wrapped_artifact_internal(
            wrapped_artifact,
            set(),
            policy=effective_policy,
            agent_card=synthetic_card,
        )

    def create_chain_of_custody(self, artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a chain of custody document for multi-agent workflows

        Args:
            artifacts: List of JACS-wrapped artifacts

        Returns:
            Chain of custody document
        """
        chain = []

        for artifact in artifacts:
            if sig := artifact.get("jacsSignature"):
                entry = {
                    "artifactId": artifact.get("jacsId"),
                    "artifactType": artifact.get("jacsType"),
                    "timestamp": artifact.get("jacsVersionDate"),
                    "agentId": sig.get("agentID"),
                    "agentVersion": sig.get("agentVersion"),
                    "signatureHash": sig.get("publicKeyHash")
                }
                chain.append(entry)

        return {
            "chainOfCustody": chain,
            "created": datetime.utcnow().isoformat() + "Z",
            "totalArtifacts": len(chain)
        }

    def agent_card_to_dict(self, agent_card: A2AAgentCard) -> Dict[str, Any]:
        """Convert A2AAgentCard to dictionary for JSON serialization (camelCase keys)"""
        def to_camel(name: str) -> str:
            parts = name.split("_")
            return parts[0] + "".join(p.capitalize() for p in parts[1:])

        def convert(obj):
            if hasattr(obj, '__dataclass_fields__'):
                result = {}
                for field_name in obj.__dataclass_fields__:
                    value = getattr(obj, field_name)
                    if value is not None:
                        key = to_camel(field_name)
                        if isinstance(value, list):
                            result[key] = [convert(item) for item in value]
                        elif isinstance(value, dict):
                            result[key] = {k: convert(v) for k, v in value.items()}
                        else:
                            result[key] = convert(value)
                return result
            return obj

        return convert(agent_card)

    def generate_well_known_documents(
        self,
        agent_card: A2AAgentCard,
        jws_signature: str,
        public_key_b64: str,
        agent_data: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """Generate .well-known documents for A2A integration (v0.4.0)

        Args:
            agent_card: The A2A Agent Card
            jws_signature: JWS signature of the Agent Card
            public_key_b64: Base64-encoded public key
            agent_data: JACS agent data

        Returns:
            Dictionary mapping paths to document contents
        """
        documents = {}
        key_algorithm = agent_data.get("keyAlgorithm", "pq2025")
        post_quantum = any(
            marker in str(key_algorithm).lower()
            for marker in ["pq2025", "ml-dsa"]
        )

        # 1. Agent Card with embedded signature (v0.4.0)
        card_dict = self.agent_card_to_dict(agent_card)
        card_dict["signatures"] = [{"jws": jws_signature}]
        documents["/.well-known/agent-card.json"] = card_dict

        # 2. JWK Set for A2A verifiers
        documents["/.well-known/jwks.json"] = self._build_jwks(public_key_b64, agent_data)

        # 3. JACS Agent Descriptor
        documents["/.well-known/jacs-agent.json"] = {
            "jacsVersion": "1.0",
            "agentId": agent_data.get("jacsId"),
            "agentVersion": agent_data.get("jacsVersion"),
            "agentType": agent_data.get("jacsAgentType"),
            "publicKeyHash": _sha256_hex(public_key_b64),
            "keyAlgorithm": key_algorithm,
            "capabilities": {
                "signing": True,
                "verification": True,
                "postQuantum": post_quantum
            },
            "schemas": {
                "agent": "https://jacs.ai/schemas/agent/v1/agent.schema.json",
                "header": "https://jacs.ai/schemas/header/v1/header.schema.json",
                "signature": "https://jacs.ai/schemas/components/signature/v1/signature.schema.json"
            },
            "endpoints": {
                "verify": "/jacs/verify",
                "sign": "/jacs/sign",
                "agent": "/jacs/agent"
            }
        }

        # 4. JACS Public Key
        documents["/.well-known/jacs-pubkey.json"] = {
            "publicKey": public_key_b64,
            "publicKeyHash": _sha256_hex(public_key_b64),
            "algorithm": key_algorithm,
            "agentId": agent_data.get("jacsId"),
            "agentVersion": agent_data.get("jacsVersion"),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        # 5. Extension descriptor
        documents["/.well-known/jacs-extension.json"] = self.create_extension_descriptor()

        return documents

    def _verify_wrapped_artifact_internal(
        self,
        wrapped_artifact: Dict[str, Any],
        visited: Set[str],
        policy: Optional[str] = None,
        agent_card: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        artifact_id = wrapped_artifact.get("jacsId")
        if artifact_id and artifact_id in visited:
            raise ValueError(f"Cycle detected in parent signature chain at artifact {artifact_id}")
        if artifact_id:
            visited.add(artifact_id)

        try:
            wrapped_json = json.dumps(wrapped_artifact)
            verify_with_policy = _get_configured_callable(
                self.client._agent,
                "verify_a2a_artifact_with_policy",
            )
            verify_canonical = _get_configured_callable(
                self.client._agent,
                "verify_a2a_artifact",
            )
            verify_legacy = _get_configured_callable(
                self.client._agent,
                "verify_response",
            )

            canonical: Dict[str, Any]
            if policy and agent_card and verify_with_policy is not None:
                canonical_json = verify_with_policy(
                    wrapped_json,
                    json.dumps(agent_card),
                    policy,
                )
                canonical = json.loads(canonical_json)
            elif verify_canonical is not None:
                canonical_json = verify_canonical(wrapped_json)
                canonical = json.loads(canonical_json)
            elif verify_legacy is not None:
                signature = wrapped_artifact.get("jacsSignature")
                signer_id = signature.get("agentID", "") if isinstance(signature, dict) else ""
                local_agent_id = getattr(self.client, "agent_id", None)
                try:
                    verification_result = verify_legacy(wrapped_json)
                    if isinstance(verification_result, bool):
                        valid = verification_result
                    elif isinstance(verification_result, dict):
                        valid = True
                    else:
                        valid = bool(verification_result)
                    status: Any = (
                        "SelfSigned"
                        if valid and signer_id and signer_id == local_agent_id
                        else "Verified"
                        if valid
                        else "Invalid"
                    )
                except Exception as exc:
                    valid = False
                    status = {"Invalid": {"reason": str(exc)}}

                parent_results = []
                parents = wrapped_artifact.get("jacsParentSignatures")
                if isinstance(parents, list):
                    for index, parent in enumerate(parents):
                        if not isinstance(parent, dict):
                            continue
                        parent_result = self._verify_wrapped_artifact_internal(parent, visited)
                        parent_results.append(
                            {
                                "index": index,
                                "artifactId": str(parent.get("jacsId", "")),
                                "signerId": str(parent_result.get("signerId", "")),
                                "status": parent_result.get("status"),
                                "verified": bool(parent_result.get("valid", False)),
                            }
                        )

                canonical = _canonical_result_from_wrapped_artifact(
                    wrapped_artifact,
                    valid=valid,
                    status=status,
                    parent_results=parent_results,
                )
            else:
                raise AttributeError(
                    "A2A verification requires one of verify_a2a_artifact_with_policy(), "
                    "verify_a2a_artifact(), or verify_response() on client._agent."
                )

            if policy and agent_card and "trustAssessment" not in canonical:
                trust_assessment = _build_trust_assessment(self.client, policy, agent_card)
                canonical = {
                    **canonical,
                    "trustLevel": trust_assessment["trustLevel"],
                    "trustAssessment": trust_assessment,
                }
                if not trust_assessment["allowed"]:
                    canonical["valid"] = False
                    canonical["status"] = {"Invalid": {"reason": trust_assessment["reason"]}}

            if "parentVerificationResults" not in canonical:
                canonical["parentVerificationResults"] = []
            if "parentSignaturesValid" not in canonical:
                parent_results = canonical.get("parentVerificationResults", [])
                canonical["parentSignaturesValid"] = all(
                    bool(parent.get("verified", False))
                    for parent in parent_results
                    if isinstance(parent, dict)
                )

            result = _canonical_result_from_wrapped_artifact(
                wrapped_artifact,
                valid=bool(canonical.get("valid", False)),
                status=canonical.get("status"),
                parent_results=canonical.get("parentVerificationResults"),
                trust_assessment=canonical.get("trustAssessment"),
            )
            return _A2AVerificationResult(result)
        finally:
            if artifact_id:
                visited.discard(artifact_id)

    def _build_jwks(
        self, public_key_b64: str, agent_data: Dict[str, Any]
    ) -> Dict[str, List[Dict[str, Any]]]:
        jwks = agent_data.get("jwks")
        if isinstance(jwks, dict) and isinstance(jwks.get("keys"), list):
            return jwks

        jwk = agent_data.get("jwk")
        if isinstance(jwk, dict):
            return {"keys": [jwk]}

        try:
            key_bytes = base64.b64decode(public_key_b64, validate=False)
        except Exception:
            return {"keys": []}

        key_algorithm = str(agent_data.get("keyAlgorithm", "")).lower()
        kid = str(agent_data.get("jacsId", "jacs-agent"))

        if len(key_bytes) == 32:
            return {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": base64.urlsafe_b64encode(key_bytes).decode("utf-8").rstrip("="),
                        "kid": kid,
                        "use": "sig",
                        "alg": "EdDSA",
                    }
                ]
            }

        # For non-Ed25519 keys, callers can pass jwk/jwks in agent_data.
        alg = self._infer_jws_alg(key_algorithm)
        if alg:
            return {"keys": [{"kid": kid, "use": "sig", "alg": alg}]}

        return {"keys": []}

    @staticmethod
    def _infer_jws_alg(key_algorithm: str) -> Optional[str]:
        if "ring-ed25519" in key_algorithm or "ed25519" in key_algorithm:
            return "EdDSA"
        if "rsa" in key_algorithm:
            return "RS256"
        if "ecdsa" in key_algorithm or "es256" in key_algorithm:
            return "ES256"
        return None

    @staticmethod
    def _slugify(name: str) -> str:
        """Convert a name to a URL-friendly slug for skill IDs."""
        slug = name.lower().replace(" ", "-").replace("_", "-")
        return "".join(c for c in slug if c.isalnum() or c == "-")

    @staticmethod
    def _derive_tags(service_name: str, fn_name: str) -> List[str]:
        """Derive tags from service/function context."""
        tags = ["jacs"]
        service_slug = JACSA2AIntegration._slugify(service_name)
        fn_slug = JACSA2AIntegration._slugify(fn_name)
        if service_slug != fn_slug:
            tags.append(service_slug)
        tags.append(fn_slug)
        return tags


# Example usage functions
def example_basic_usage():
    """Basic example of using JACS A2A integration (v0.4.0)"""
    from .client import JacsClient

    client = JacsClient("jacs.config.json")
    a2a = JACSA2AIntegration(client)

    agent_data = {
        "jacsId": "example-agent-123",
        "jacsVersion": "v1.0.0",
        "jacsName": "Example Python Agent",
        "jacsDescription": "A Python agent with A2A support",
        "jacsAgentType": "ai",
        "jacsServices": [{
            "name": "Text Analysis",
            "serviceDescription": "Analyzes text using NLP",
            "successDescription": "Text successfully analyzed",
            "failureDescription": "Analysis failed",
            "tools": [{
                "url": "/api/analyze",
                "function": {
                    "name": "analyze_text",
                    "description": "Analyze text and extract insights",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "text": {"type": "string"},
                            "language": {"type": "string"}
                        },
                        "required": ["text"]
                    }
                }
            }]
        }]
    }

    agent_card = a2a.export_agent_card(agent_data)
    print("Agent Card created:")
    print(f"  Name: {agent_card.name}")
    print(f"  Version: {agent_card.version}")
    print(f"  Protocol Versions: {agent_card.protocol_versions}")
    print(f"  Skills: {len(agent_card.skills)}")
    print(f"  Interfaces: {len(agent_card.supported_interfaces)}")

    task = {
        "taskId": "task-456",
        "operation": "analyze_text",
        "input": {"text": "Hello world", "language": "en"},
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    wrapped_task = a2a.sign_artifact(task, "task")
    print(f"\nWrapped task ID: {wrapped_task['jacsId']}")

    verification = a2a.verify_wrapped_artifact(wrapped_task)
    print(f"Verification: {'PASSED' if verification['valid'] else 'FAILED'}")

    return agent_card, wrapped_task


if __name__ == "__main__":
    agent_card, wrapped_task = example_basic_usage()

    print("\n=== Agent Card JSON ===")
    a2a = JACSA2AIntegration.from_config("jacs.config.json")
    print(json.dumps(a2a.agent_card_to_dict(agent_card), indent=2))

    print("\n=== Wrapped Task JSON ===")
    print(json.dumps(wrapped_task, indent=2))
