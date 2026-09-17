"""Base adapter for JACS framework integrations.

Wraps a JacsClient instance and provides sign/verify primitives that
framework-specific adapters can hook into. Signing and verification fail
closed by default; legacy fallback behavior requires explicit opt-ins.

When ``attest=True`` is passed, the adapter produces attestation
documents instead of plain signatures.  If the underlying client
does not support attestation (feature not compiled in), the adapter raises
unless plain-signature fallback is explicitly enabled.

Example:
    from jacs.adapters.base import BaseJacsAdapter
    from jacs.client import JacsClient

    adapter = BaseJacsAdapter(client=JacsClient.ephemeral())
    signed = adapter.sign_output({"result": "ok"})
    payload = adapter.verify_input(signed)

    # With attestation:
    adapter = BaseJacsAdapter(client=JacsClient.ephemeral(), attest=True)
    attested = adapter.sign_output({"result": "ok"})
"""

import json
import logging
from typing import Any, Dict, List, Optional

from .._signed_document import require_portable_v2_signed_raw

logger = logging.getLogger("jacs.adapters")


class BaseJacsAdapter:
    """Base class for all JACS framework adapters.

    Wraps a JacsClient instance and provides sign/verify primitives
    that framework-specific adapters can hook into.

    Args:
        client: An existing JacsClient instance to use. If None, one
            will be created via quickstart or ephemeral depending on
            the other parameters.
        config_path: Path to jacs.config.json. If provided (and no
            client), a JacsClient will be created from this config.
        strict: If True, sign/verify failures raise exceptions and all
            compatibility fallbacks are disabled.
        allow_unverified_passthrough: Dangerous compatibility option that
            exposes original input after failed verification. Default False.
        allow_unsigned_output: Dangerous compatibility option that exposes
            original output after signing fails. Default False.
        allow_plain_signature_fallback: Compatibility option that permits an
            attestation request to downgrade to a plain signature when
            attestation creation fails. Default False.
        attest: If True, produce attestation documents instead of
            plain signatures. Attestation failures raise unless
            ``allow_plain_signature_fallback`` is enabled. Default False.
        default_claims: A list of claim dicts to include in every
            attestation. Only used when attest=True.
    """

    def __init__(
        self,
        client: Optional[Any] = None,
        config_path: Optional[str] = None,
        strict: bool = False,
        allow_unverified_passthrough: bool = False,
        allow_unsigned_output: bool = False,
        allow_plain_signature_fallback: bool = False,
        attest: bool = False,
        default_claims: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self._strict = strict
        # Verification is a trust boundary and fails closed independently of
        # permissive signing behavior. Keep the legacy passthrough available
        # only behind an explicit dangerous opt-in; strict mode always wins.
        self._allow_unverified_passthrough = (
            allow_unverified_passthrough is True and strict is not True
        )
        self._allow_unsigned_output = (
            allow_unsigned_output is True and strict is not True
        )
        self._allow_plain_signature_fallback = (
            allow_plain_signature_fallback is True and strict is not True
        )
        self._attest = attest
        self._default_claims = default_claims or []

        if client is not None:
            self._client = client
        else:
            # Lazy import to avoid circular dependency
            from ..client import JacsClient

            if config_path is not None:
                self._client = JacsClient(config_path=config_path, strict=strict)
            else:
                self._client = JacsClient.quickstart(
                    name="jacs-adapter",
                    domain="localhost",
                    description="JACS framework adapter agent",
                    strict=strict,
                )

    @property
    def client(self) -> Any:
        """The underlying JacsClient instance."""
        return self._client

    @property
    def strict(self) -> bool:
        """Whether the adapter is in strict mode."""
        return self._strict

    @property
    def allow_unverified_passthrough(self) -> bool:
        """Whether failed verification may expose the original input.

        This compatibility behavior is unsafe at trust boundaries and is
        disabled by default. ``strict=True`` disables it even when requested.
        """
        return self._allow_unverified_passthrough

    @property
    def allow_unsigned_output(self) -> bool:
        """Whether a signing failure may expose the original output."""
        return self._allow_unsigned_output

    @property
    def allow_plain_signature_fallback(self) -> bool:
        """Whether failed attestation creation may downgrade to signing."""
        return self._allow_plain_signature_fallback

    @property
    def attest(self) -> bool:
        """Whether the adapter produces attestations instead of plain signatures."""
        return self._attest

    @property
    def default_claims(self) -> List[Dict[str, Any]]:
        """Default claims included in every attestation."""
        return self._default_claims

    def _build_attestation_params(
        self,
        data: Any,
        extra_claims: Optional[List[Dict[str, Any]]] = None,
    ) -> tuple:
        """Build subject and claims for an attestation from arbitrary data.

        Returns:
            Tuple of (subject_dict, claims_list).
        """
        # Serialize data for hashing
        if isinstance(data, str):
            data_str = data
        else:
            data_str = json.dumps(data, sort_keys=True, default=str)

        from .. import hash_string as _hash_string_native

        digest = _hash_string_native(data_str)

        subject = {
            "type": "adapter_output",
            "id": f"urn:jacs:adapter:{digest[:16]}",
            "digests": {"sha256": digest},
        }

        claims = list(self._default_claims)
        if extra_claims:
            claims.extend(extra_claims)
        if not claims:
            claims = [{"name": "signed_by_adapter", "value": "true", "confidence": 1.0}]

        return subject, claims

    def sign_output(
        self, data: Any, extra_claims: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """Sign data and return signed JSON string.

        When ``attest=True``, this produces an attestation document.
        When ``attest=False`` (default), this produces a plain signed
        document.

        Attestation failure raises by default. Plain-signature downgrade is
        available only with ``allow_plain_signature_fallback=True``.

        Args:
            data: The data to sign. Can be a dict, string, or any
                JSON-serializable value.
            extra_claims: Additional claims to include in the
                attestation (only used when attest=True).

        Returns:
            Signed JSON string.

        Raises:
            SigningError: If signing or requested attestation creation fails.
        """
        if self._attest:
            return self._sign_as_attestation(data, extra_claims)
        signed_doc = self._client.sign_message(data)
        return self._require_signed_output(signed_doc.raw_json, "JACS adapter signer")

    @staticmethod
    def _require_signed_output(raw_json: Any, context: str) -> str:
        from ..types import SigningError

        try:
            return require_portable_v2_signed_raw(raw_json, context=context)
        except ValueError as exc:
            raise SigningError(str(exc)) from exc

    def _sign_as_attestation(
        self, data: Any, extra_claims: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """Create an attestation, applying only explicitly enabled fallback."""
        try:
            subject, claims = self._build_attestation_params(data, extra_claims)
            signed_doc = self._client.create_attestation(
                subject=subject,
                claims=claims,
            )
            return self._require_signed_output(
                signed_doc.raw_json,
                "JACS attestation signer",
            )
        except Exception as exc:
            logger.warning("JACS attestation creation failed: %s", exc)
            if not self._allow_plain_signature_fallback:
                raise
            logger.warning("JACS falling back to a plain signature")
            signed_doc = self._client.sign_message(data)
            return self._require_signed_output(
                signed_doc.raw_json,
                "JACS adapter signer",
            )

    def verify_input(self, signed_json: str) -> Any:
        """Verify signed JSON and return the original payload.

        Verifies the cryptographic signature and extracts the payload
        from the JACS document envelope.

        Args:
            signed_json: A signed JACS document as a JSON string.

        Returns:
            The verified payload (dict or other Python object).

        Raises:
            VerificationError: If verification fails.
        """
        from ..types import VerificationError

        result = self._client.verify(signed_json)
        if isinstance(result, dict):
            valid = result.get("valid") is True
            errors = result.get("errors", [])
        else:
            valid = getattr(result, "valid", False) is True
            errors = getattr(result, "errors", [])
        if not valid:
            raise VerificationError(f"Verification failed: {errors}")
        # Extract the payload from the signed document
        doc = json.loads(signed_json)
        return doc.get("jacsDocument", doc.get("content", doc))

    def sign_output_or_passthrough(self, data: Any) -> str:
        """Sign if possible, passthrough if not.

        Signing failures raise by default. When the dangerous
        ``allow_unsigned_output`` compatibility option is enabled, failures
        are logged and the original data is returned as JSON.

        Args:
            data: The data to sign.

        Returns:
            Signed JSON string on success, or JSON-serialized original data
            only when ``allow_unsigned_output`` is explicitly enabled.
        """
        try:
            return self.sign_output(data)
        except Exception as exc:
            logger.warning("JACS signing failed: %s", exc)
            if not self._allow_unsigned_output:
                raise
            if isinstance(data, str):
                return data
            return json.dumps(data)

    def verify_input_or_passthrough(self, signed_json: str) -> Any:
        """Verify if possible, passthrough if not.

        Verification failures raise by default. When the dangerous
        ``allow_unverified_passthrough`` compatibility option is enabled,
        failures are logged and the original input is returned as-is.

        Args:
            signed_json: A signed JACS document as a JSON string.

        Returns:
            Verified payload on success, or the original parsed JSON only
            when ``allow_unverified_passthrough`` is explicitly enabled.
        """
        try:
            return self.verify_input(signed_json)
        except Exception as exc:
            logger.warning("JACS verification failed: %s", exc)
            if not self._allow_unverified_passthrough:
                raise
            try:
                return json.loads(signed_json)
            except json.JSONDecodeError:
                return signed_json

    # ------------------------------------------------------------------
    # A2A helpers
    # ------------------------------------------------------------------

    def export_agent_card(
        self,
        url: Optional[str] = None,
        skills: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Export this adapter's agent as an A2A Agent Card dict.

        Delegates to :meth:`JACSA2AIntegration.export_agent_card` via
        the underlying :class:`JacsClient`, then converts to a plain
        dict for framework-agnostic consumption.

        Args:
            url: Base URL for the agent's A2A endpoint. Injected as
                ``jacsAgentDomain`` so the card's
                ``supportedInterfaces`` contains a real URL.
            skills: Optional list of JACS service dicts to include
                as A2A skills.

        Returns:
            The Agent Card as a JSON-serialisable dict.
        """
        from ..a2a import JACSA2AIntegration

        card = self._client.export_agent_card(url=url, skills=skills)
        integration = JACSA2AIntegration(self._client)
        return integration.agent_card_to_dict(card)

    def assess_trust(
        self,
        agent_card_json: str,
        policy: str = "verified",
    ) -> Dict[str, Any]:
        """Assess trust for a remote agent card.

        Applies a trust policy against a raw Agent Card JSON string.

        Policies:
            - ``"open"``: Always allowed.
            - ``"verified"``: Allowed only if the card declares the
              JACS provenance extension
              (``urn:jacs:provenance-v1``).
            - ``"strict"``: Allowed only if the agent is in the
              local trust store.

        Args:
            agent_card_json: JSON string of the remote Agent Card.
            policy: Trust policy to apply (default ``"verified"``).

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
        from ..a2a_discovery import _evaluate_trust_policy, _validate_trust_policy

        effective_policy = _validate_trust_policy(policy)
        card = json.loads(agent_card_json)

        # Prefer binding-core delegation when available
        if hasattr(self._client, "_agent"):
            try:
                canonical_json = self._client._agent.assess_a2a_agent(
                    agent_card_json, effective_policy
                )
                trust = json.loads(canonical_json)
                return {
                    "card": card,
                    "jacs_registered": trust.get("jacsRegistered") is True,
                    "trust_level": trust.get("trustLevel", "untrusted"),
                    "allowed": trust.get("allowed") is True,
                }
            except (ImportError, AttributeError, TypeError):
                logger.warning(
                    "Falling back to local trust policy evaluation "
                    "— binding-core assess_a2a_agent unavailable"
                )

        # Fallback: deprecated local logic
        trust = _evaluate_trust_policy(
            card,
            policy=effective_policy,
            is_trusted=getattr(self._client, "is_trusted", None),
        )

        return {
            "card": card,
            **trust,
        }
