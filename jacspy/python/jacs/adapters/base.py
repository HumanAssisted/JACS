"""Base adapter for JACS framework integrations.

Wraps a JacsClient instance and provides sign/verify primitives that
framework-specific adapters can hook into. Supports strict mode
(raise on failures) and permissive mode (log and passthrough).

Example:
    from jacs.adapters.base import BaseJacsAdapter
    from jacs.client import JacsClient

    adapter = BaseJacsAdapter(client=JacsClient.ephemeral())
    signed = adapter.sign_output({"result": "ok"})
    payload = adapter.verify_input(signed)
"""

import json
import logging
from typing import Any, Dict, List, Optional

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
        strict: If True, sign/verify failures raise exceptions.
            If False (default), failures are logged and the original
            data is returned unchanged.
    """

    def __init__(
        self,
        client: Optional[Any] = None,
        config_path: Optional[str] = None,
        strict: bool = False,
    ) -> None:
        self._strict = strict

        if client is not None:
            self._client = client
        else:
            # Lazy import to avoid circular dependency
            from ..client import JacsClient

            if config_path is not None:
                self._client = JacsClient(config_path=config_path, strict=strict)
            else:
                self._client = JacsClient.quickstart(strict=strict)

    @property
    def client(self) -> Any:
        """The underlying JacsClient instance."""
        return self._client

    @property
    def strict(self) -> bool:
        """Whether the adapter is in strict mode."""
        return self._strict

    def sign_output(self, data: Any) -> str:
        """Sign data and return signed JSON string.

        Uses JacsClient.sign_message which wraps data into a JACS
        document envelope with cryptographic signature.

        Args:
            data: The data to sign. Can be a dict, string, or any
                JSON-serializable value.

        Returns:
            Signed JSON string.

        Raises:
            SigningError: If signing fails and strict mode is enabled.
        """
        signed_doc = self._client.sign_message(data)
        return signed_doc.raw_json

    def verify_input(self, signed_json: str) -> Any:
        """Verify signed JSON and return the original payload.

        Verifies the cryptographic signature and extracts the payload
        from the JACS document envelope.

        Args:
            signed_json: A signed JACS document as a JSON string.

        Returns:
            The verified payload (dict or other Python object).

        Raises:
            VerificationError: If verification fails and strict mode
                is enabled.
        """
        from ..types import VerificationError

        result = self._client.verify(signed_json)
        if not result.valid:
            raise VerificationError(
                f"Verification failed: {result.errors}"
            )
        # Extract the payload from the signed document
        doc = json.loads(signed_json)
        return doc.get("jacsDocument", doc.get("content", doc))

    def sign_output_or_passthrough(self, data: Any) -> str:
        """Sign if possible, passthrough if not.

        In strict mode, signing failures raise. In permissive mode,
        failures are logged and the original data is returned as JSON.

        Args:
            data: The data to sign.

        Returns:
            Signed JSON string on success, or JSON-serialized original
            data on failure (permissive mode only).
        """
        try:
            return self.sign_output(data)
        except Exception as exc:
            if self._strict:
                raise
            logger.warning("JACS signing failed (passthrough): %s", exc)
            if isinstance(data, str):
                return data
            return json.dumps(data)

    def verify_input_or_passthrough(self, signed_json: str) -> Any:
        """Verify if possible, passthrough if not.

        In strict mode, verification failures raise. In permissive
        mode, failures are logged and the original input is returned
        as-is (parsed from JSON if possible).

        Args:
            signed_json: A signed JACS document as a JSON string.

        Returns:
            Verified payload on success, or the original parsed JSON
            on failure (permissive mode only).
        """
        try:
            return self.verify_input(signed_json)
        except Exception as exc:
            if self._strict:
                raise
            logger.warning("JACS verification failed (passthrough): %s", exc)
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
              (``urn:hai.ai:jacs-provenance-v1``).
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
        from ..a2a_discovery import _has_jacs_extension, _extract_agent_id

        if policy not in ("open", "verified", "strict"):
            raise ValueError(
                f"Invalid trust policy: {policy!r}. "
                "Must be 'open', 'verified', or 'strict'."
            )

        card = json.loads(agent_card_json)
        jacs_registered = _has_jacs_extension(card)

        trust_level = "untrusted"
        if jacs_registered:
            trust_level = "jacs_registered"

        if policy == "strict":
            agent_id = _extract_agent_id(card)
            if agent_id:
                try:
                    if self._client.is_trusted(agent_id):
                        trust_level = "trusted"
                except Exception:
                    logger.debug("Trust store lookup failed for %s", agent_id)

        if policy == "open":
            allowed = True
        elif policy == "verified":
            allowed = jacs_registered
        elif policy == "strict":
            allowed = trust_level == "trusted"
        else:
            allowed = False

        return {
            "card": card,
            "jacs_registered": jacs_registered,
            "trust_level": trust_level,
            "allowed": allowed,
        }
