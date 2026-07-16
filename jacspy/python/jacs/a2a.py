"""
A2A (Agent-to-Agent) Protocol Integration for JACS Python

This module provides Python bindings for JACS's A2A protocol integration,
enabling JACS agents to participate in the Agent-to-Agent communication protocol.

Implements A2A protocol v0.4.0 (September 2025).
"""

from __future__ import annotations

import json
import logging
import os
import warnings
from typing import Dict, List, Optional, Any, TYPE_CHECKING, Set
from dataclasses import dataclass
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

def _hash_public_key_base64(public_key_b64: str) -> str:
    from . import hash_public_key_base64 as _hash_public_key_base64_native

    return _hash_public_key_base64_native(public_key_b64)


def _build_jwk_set_from_public_key(
    public_key_b64: str, key_algorithm: str, key_id: str
) -> Dict[str, Any]:
    from . import build_jwk_set_from_public_key as _build_jwk_set_from_public_key_native

    return json.loads(
        _build_jwk_set_from_public_key_native(public_key_b64, key_algorithm, key_id)
    )


def _build_trust_block(trust_assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Map canonical trustAssessment data to the wrapper's legacy trust block."""
    allowed = trust_assessment.get("allowed") is True
    return {
        "allowed": allowed,
        "jacs_registered": trust_assessment.get("jacsRegistered") is True,
        "trust_level": (
            _legacy_trust_level(trust_assessment.get("trustLevel"))
            if allowed
            else "untrusted"
        ),
        "reason": trust_assessment.get("reason", ""),
        "policy": trust_assessment.get("policy"),
        "first_contact": trust_assessment.get("firstContact") is True,
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
    normalized_policy = str(policy).lower()
    policy_name = _canonical_policy_name(normalized_policy) or "Verified"

    if normalized_policy == "open":
        allowed = True
        reason = (
            "Open policy: agent allowed without native cryptographic assessment; "
            "no identity assurance is claimed"
        )
    else:
        # A self-advertised extension or a boolean trust-store lookup cannot
        # replace native card/JWKS/binding verification. The native assessor
        # performs secure same-origin fetches, durable TOFU pinning, and strict
        # native-root binding verification. If it is unavailable, every
        # identity-bearing policy fails closed.
        allowed = False
        reason = (
            f"{policy_name} policy: native cryptographic assessment is unavailable; "
            "an Agent Card extension or local trust-store name alone does not prove identity"
        )

    return {
        "allowed": allowed,
        "trustLevel": "Untrusted",
        "reason": reason,
        "jacsRegistered": jacs_registered,
        "agentId": agent_id,
        "policy": policy_name,
    }


def _normalize_status(status: Any, *, valid: bool, reason: str = "") -> Any:
    if valid and isinstance(status, str) and status in {"Verified", "SelfSigned"}:
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


def _normalize_parent_result(parent: Any) -> Dict[str, Any]:
    if not isinstance(parent, dict):
        return {
            "index": 0,
            "artifactId": "",
            "signerId": "",
            "status": {"Invalid": {"reason": "malformed canonical parent result"}},
            "verified": False,
        }
    explicit_verified = (
        parent.get("verified") is True
        if "verified" in parent
        else parent.get("valid") is True
    )
    status = parent.get("status")
    verified = explicit_verified and status in {"Verified", "SelfSigned"}
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
    trust_assessment: Any = None,
    parent_summary_valid: Optional[bool] = None,
    canonical_provenance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if canonical_provenance is None:
        # Parsed wrapper fields are attacker-controlled until the canonical
        # native A2A verifier authenticates and projects them.  A generic
        # verify_response() boolean has no A2A provenance contract, so never
        # copy its signer, version, type, timestamp, or payload into a result.
        signer_id = ""
        signer_version = ""
        artifact_type = ""
        timestamp = ""
        original_artifact = {}
        canonical_provenance_complete = False
    else:
        # Canonical native verification results are an authenticated output
        # contract. Never backfill a missing field from the attacker-supplied
        # wrapper: that would turn parsed input into purported verified data.
        signer_id = canonical_provenance.get("signerId")
        signer_version = canonical_provenance.get("signerVersion")
        artifact_type = canonical_provenance.get("artifactType")
        timestamp = canonical_provenance.get("timestamp")
        original_artifact = canonical_provenance.get("originalArtifact")
        canonical_provenance_complete = (
            isinstance(signer_id, str)
            and bool(signer_id)
            and isinstance(signer_version, str)
            and bool(signer_version)
            and isinstance(artifact_type, str)
            and bool(artifact_type)
            and isinstance(timestamp, str)
            and bool(timestamp)
            and isinstance(original_artifact, dict)
        )
        if not isinstance(signer_id, str):
            signer_id = ""
        if not isinstance(signer_version, str):
            signer_version = ""
        if not isinstance(artifact_type, str):
            artifact_type = ""
        if not isinstance(timestamp, str):
            timestamp = ""
        if not isinstance(original_artifact, dict):
            original_artifact = {}
    normalized_parent_results = [
        _normalize_parent_result(parent_result)
        for parent_result in (parent_results or [])
    ]
    declared_parents = wrapped_artifact.get("jacsParentSignatures")
    declared_parent_count = len(declared_parents) if isinstance(declared_parents, list) else 0
    parents_valid = canonical_provenance is not None and (
        len(normalized_parent_results) == declared_parent_count
        and all(parent["verified"] is True for parent in normalized_parent_results)
        and parent_summary_valid is not False
    )
    normalized_trust: Optional[Dict[str, Any]] = None
    trust_allows = True
    if trust_assessment is not None:
        if isinstance(trust_assessment, dict):
            allowed = trust_assessment.get("allowed") is True
            trust_level = _canonical_trust_level(trust_assessment.get("trustLevel"))
            normalized_trust = {
                "allowed": allowed,
                "trustLevel": trust_level if allowed else "Untrusted",
                "reason": str(trust_assessment.get("reason", "")),
                "jacsRegistered": trust_assessment.get("jacsRegistered") is True,
                "agentId": trust_assessment.get("agentId"),
                "policy": _canonical_policy_name(trust_assessment.get("policy")) or "Verified",
                "firstContact": trust_assessment.get("firstContact") is True,
            }
        else:
            normalized_trust = {
                "allowed": False,
                "trustLevel": "Untrusted",
                "reason": "malformed canonical trust assessment",
                "jacsRegistered": False,
                "agentId": None,
                "policy": "Verified",
                "firstContact": False,
            }
        trust_allows = normalized_trust["allowed"] is True
    effective_valid = (
        valid is True
        and parents_valid
        and canonical_provenance_complete
        and trust_allows
    )
    failure_reason = (
        "canonical verifier omitted authenticated provenance fields"
        if not canonical_provenance_complete
        else "parent signature verification failed or was incomplete"
        if not parents_valid
        else normalized_trust.get("reason", "trust policy denied the signer")
        if normalized_trust is not None and not trust_allows
        else "signature verification failed"
    )

    result: Dict[str, Any] = {
        "status": _normalize_status(status, valid=effective_valid, reason=failure_reason),
        "valid": effective_valid,
        "signerId": signer_id,
        "signerVersion": signer_version,
        "artifactType": artifact_type,
        "timestamp": timestamp,
        "parentSignaturesValid": parents_valid,
        "parentVerificationResults": normalized_parent_results,
        "originalArtifact": original_artifact,
    }
    if normalized_trust is not None:
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
    SUPPORTED_ALGORITHMS = ["ring-Ed25519", "pq2025"]

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

        Serves all six identity-bound ``/.well-known/`` endpoints required for A2A
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

        # Use explicit A2A skills when present. Retired JACS service schemas are
        # intentionally ignored for Agent Card skill generation.
        skills = self._normalize_a2a_skills(
            agent_data.get("skills") or agent_data.get("a2aSkills") or []
        )

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

    def _normalize_a2a_skills(self, raw_skills: List[Dict[str, Any]]) -> List[A2AAgentSkill]:
        """Normalize explicit A2A skills for Agent Card export (v0.4.0)."""
        skills = []

        for raw_skill in raw_skills:
            if isinstance(raw_skill, A2AAgentSkill):
                skills.append(raw_skill)
                continue

            name = raw_skill.get("name", raw_skill.get("id", "unnamed"))
            skills.append(A2AAgentSkill(
                id=raw_skill.get("id", self._slugify(name)),
                name=name,
                description=raw_skill.get("description", ""),
                tags=raw_skill.get("tags", ["jacs"]),
                examples=raw_skill.get("examples"),
                input_modes=raw_skill.get("inputModes") or raw_skill.get("input_modes"),
                output_modes=raw_skill.get("outputModes") or raw_skill.get("output_modes"),
                security=raw_skill.get("security"),
            ))

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
            artifact_type: Type of artifact (e.g., ``"artifact"``, ``"result"``).
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
            artifact_type: Type of artifact (e.g., ``"artifact"``, ``"result"``).
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
            "jacs_registered": canonical.get("jacsRegistered") is True,
            "trust_level": (
                _legacy_trust_level(canonical.get("trustLevel"))
                if canonical.get("allowed") is True
                else "untrusted"
            ),
            "allowed": canonical.get("allowed") is True,
            "reason": canonical.get("reason", ""),
            "policy": canonical.get("policy", _canonical_policy_name(effective_policy)),
            "first_contact": canonical.get("firstContact") is True,
        }

    def trust_a2a_agent(self, agent_document_json: str, public_key_pem: str) -> str:
        """Explicitly trust a native JACS identity used by A2A strict mode.

        An Agent Card is self-advertised discovery metadata and is never
        sufficient to create native identity trust. The caller must obtain the
        full self-signed native JACS agent document and its public key through
        an authenticated out-of-band channel. Native trust establishment then
        verifies the document before persisting a ``verified`` trust entry.

        Args:
            agent_document_json: Full native JACS agent document JSON.
            public_key_pem: Explicit native public key in PEM form.

        Returns:
            Result string from :meth:`JacsClient.trust_agent_with_key`.
        """
        if not isinstance(public_key_pem, str) or not public_key_pem.strip():
            raise ValueError(
                "Cannot establish A2A identity trust without an explicit public key"
            )
        try:
            document = json.loads(agent_document_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid native JACS agent document JSON: {exc}") from exc
        if not isinstance(document, dict) or not all(
            field in document for field in ("jacsId", "jacsVersion", "jacsSignature")
        ):
            raise ValueError(
                "trust_a2a_agent requires the full native JACS agent document, not an "
                "unauthenticated Agent Card"
            )
        trust_with_key = _get_configured_callable(self.client, "trust_agent_with_key")
        if trust_with_key is None:
            raise RuntimeError(
                "The configured JacsClient does not expose trust_agent_with_key; "
                "strict A2A trust cannot be established"
            )
        return trust_with_key(agent_document_json, public_key_pem)

    def verify_wrapped_artifact(
        self,
        wrapped_artifact: Dict[str, Any],
        assess_trust: bool = False,
        trust_policy: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify a JACS-wrapped A2A artifact.

        Affirmative verification requires the native canonical
        ``verify_a2a_artifact`` contract.  The generic ``verify_response``
        method is not an A2A fallback: even a literal ``True`` produces a
        stable invalid result with blank provenance and cannot elevate trust.

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
        """Generate identity-bound .well-known documents for A2A integration.

        Args:
            agent_card: Deprecated compatibility input; never replaces the
                native signed Agent Card.
            jws_signature: Deprecated compatibility input; never accepted as
                an identity signature.
            public_key_b64: Deprecated compatibility input.
            agent_data: Deprecated compatibility input.

        Returns:
            Dictionary mapping paths to document contents
        """
        native_generate = _get_configured_callable(
            getattr(self.client, "_agent", None),
            "generate_well_known_documents",
        )
        if native_generate is None:
            raise RuntimeError(
                "Identity-bound A2A discovery requires the native JACS generator; "
                "legacy wrapper-generated keys and signatures are not trusted"
            )
        try:
            native_pairs = json.loads(native_generate())
        except Exception as exc:
            raise RuntimeError(
                f"Identity-bound A2A discovery generation failed: {exc}"
            ) from exc
        if not isinstance(native_pairs, list):
            raise RuntimeError("Native A2A discovery result must be an array of path/document pairs")

        documents: Dict[str, Dict[str, Any]] = {}
        for item in native_pairs:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("path"), str)
                or not isinstance(item.get("document"), dict)
            ):
                raise RuntimeError("Native A2A discovery returned a malformed path/document pair")
            path = item["path"]
            if path in documents:
                raise RuntimeError(f"Native A2A discovery returned duplicate path {path!r}")
            documents[path] = item["document"]

        required_paths = {
            "/.well-known/agent-card.json",
            "/.well-known/jwks.json",
            "/.well-known/jacs-compat-binding.json",
            "/.well-known/jacs-agent.json",
            "/.well-known/jacs-pubkey.json",
            "/.well-known/jacs-extension.json",
        }
        missing = sorted(required_paths.difference(documents))
        if missing:
            raise RuntimeError(
                "Native A2A discovery omitted identity-bound documents: " + ", ".join(missing)
            )

        card = documents["/.well-known/agent-card.json"]
        metadata = card.get("metadata")
        signatures = card.get("signatures")
        if (
            not isinstance(metadata, dict)
            or metadata.get("jacsCompatBindingPath")
            != "/.well-known/jacs-compat-binding.json"
            or not isinstance(signatures, list)
            or not signatures
            or not isinstance(signatures[0], dict)
            or not signatures[0].get("jws")
            or signatures[0].get("keyId") != metadata.get("jacsCompatKid")
        ):
            raise RuntimeError("Native A2A Agent Card is missing its bound ES256 signature metadata")

        jwks = documents["/.well-known/jwks.json"].get("keys")
        if (
            not isinstance(jwks, list)
            or not any(
                isinstance(key, dict)
                and key.get("kid") == metadata.get("jacsCompatKid")
                and key.get("alg") == "ES256"
                and key.get("use") == "sig"
                for key in jwks
            )
        ):
            raise RuntimeError("Native A2A JWKS does not contain the card's ES256 signing key")
        binding = documents["/.well-known/jacs-compat-binding.json"]
        if binding.get("jacsSha256") != metadata.get("jacsCompatBindingHash"):
            raise RuntimeError("Native A2A compatibility binding hash does not match the Agent Card")

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
            canonical_is_native = False
            requires_policy_verifier = policy in {"verified", "strict"}
            if requires_policy_verifier and (agent_card is None or verify_with_policy is None):
                canonical = _canonical_result_from_wrapped_artifact(
                    wrapped_artifact,
                    valid=False,
                    status={
                        "Invalid": {
                            "reason": (
                                f"{policy.capitalize()} A2A artifact verification requires "
                                "the canonical native policy verifier; generic or legacy "
                                "verification cannot establish policy-bound trust"
                            )
                        }
                    },
                )
            elif policy and agent_card and verify_with_policy is not None:
                canonical_json = verify_with_policy(
                    wrapped_json,
                    json.dumps(agent_card),
                    policy,
                )
                canonical = json.loads(canonical_json)
                canonical_is_native = True
            elif verify_canonical is not None:
                canonical_json = verify_canonical(wrapped_json)
                canonical = json.loads(canonical_json)
                canonical_is_native = True
            elif verify_legacy is not None:
                # Generic document verification is not an A2A verification
                # contract.  Even a literal True cannot authenticate which
                # parsed fields were covered, project canonical provenance, or
                # validate the parent chain.  Do not invoke it as a fallback.
                canonical = _canonical_result_from_wrapped_artifact(
                    wrapped_artifact,
                    valid=False,
                    status={
                        "Invalid": {
                            "reason": (
                                "A2A verification requires the canonical native "
                                "verify_a2a_artifact() verifier; legacy "
                                "verify_response() cannot establish A2A validity"
                            )
                        }
                    },
                    parent_summary_valid=False,
                )
            else:
                raise AttributeError(
                    "A2A verification requires one of verify_a2a_artifact_with_policy(), "
                    "or verify_a2a_artifact() on client._agent."
                )

            if policy and agent_card and "trustAssessment" not in canonical:
                trust_assessment = (
                    _build_trust_assessment(self.client, policy, agent_card)
                    if canonical_is_native
                    else {
                        "allowed": False,
                        "trustLevel": "Untrusted",
                        "reason": (
                            "canonical native A2A verification is unavailable; "
                            "legacy verification cannot elevate trust"
                        ),
                        "jacsRegistered": False,
                        "agentId": None,
                        "policy": _canonical_policy_name(policy) or "Verified",
                        "firstContact": False,
                    }
                )
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
                    parent.get("verified") is True
                    for parent in parent_results
                    if isinstance(parent, dict)
                )
            declared_parents = wrapped_artifact.get("jacsParentSignatures")
            if (
                isinstance(declared_parents, list)
                and declared_parents
                and canonical.get("parentSignaturesValid") is not True
            ):
                canonical["valid"] = False
                canonical["status"] = {
                    "Invalid": {
                        "reason": "parent signature verification did not return literal true"
                    }
                }

            result = _canonical_result_from_wrapped_artifact(
                wrapped_artifact,
                valid=canonical.get("valid") is True,
                status=canonical.get("status"),
                parent_results=canonical.get("parentVerificationResults"),
                trust_assessment=canonical.get("trustAssessment"),
                parent_summary_valid=(
                    canonical.get("parentSignaturesValid") is True
                    if isinstance(declared_parents, list) and declared_parents
                    else None
                ),
                canonical_provenance=canonical if canonical_is_native else None,
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
            return _build_jwk_set_from_public_key(
                public_key_b64,
                str(agent_data.get("keyAlgorithm", "")),
                str(agent_data.get("jacsId", "jacs-agent")),
            )
        except Exception:
            return {"keys": []}

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
        "skills": [{
            "id": "analyze-text",
            "name": "analyze_text",
            "description": "Analyze text and extract insights",
            "tags": ["jacs", "analysis"],
        }]
    }

    agent_card = a2a.export_agent_card(agent_data)
    print("Agent Card created:")
    print(f"  Name: {agent_card.name}")
    print(f"  Version: {agent_card.version}")
    print(f"  Protocol Versions: {agent_card.protocol_versions}")
    print(f"  Skills: {len(agent_card.skills)}")
    print(f"  Interfaces: {len(agent_card.supported_interfaces)}")

    artifact = {
        "artifactId": "artifact-456",
        "operation": "analyze_text",
        "input": {"text": "Hello world", "language": "en"},
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    wrapped_artifact = a2a.sign_artifact(artifact, "artifact")
    print(f"\nWrapped artifact ID: {wrapped_artifact['jacsId']}")

    verification = a2a.verify_wrapped_artifact(wrapped_artifact)
    print(f"Verification: {'PASSED' if verification['valid'] else 'FAILED'}")

    return agent_card, wrapped_artifact


if __name__ == "__main__":
    agent_card, wrapped_artifact = example_basic_usage()

    print("\n=== Agent Card JSON ===")
    a2a = JACSA2AIntegration.from_config("jacs.config.json")
    print(json.dumps(a2a.agent_card_to_dict(agent_card), indent=2))

    print("\n=== Wrapped Task JSON ===")
    print(json.dumps(wrapped_artifact, indent=2))
