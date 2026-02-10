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
from typing import Any, Optional

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
