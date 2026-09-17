"""Structural policy for output presented as a newly signed JACS document."""

import json
from typing import Any, Dict


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def require_portable_v2_signed_document(
    value: Any,
    *,
    context: str = "JACS signer",
) -> Dict[str, Any]:
    """Require the minimum portable-v2 metadata shared by every binding.

    This is structural validation rather than cryptographic verification. It
    prevents empty, legacy-v1, and incomplete binding output from being
    represented to a caller as a newly signed document.
    """
    if not isinstance(value, dict):
        raise ValueError(f"{context} did not return a portable v2 signed document")

    signature = value.get("jacsSignature")
    signer_id = None
    if isinstance(signature, dict):
        signer_id = signature.get("agentID", signature.get("agentId"))

    if (
        not _non_empty_string(value.get("jacsId"))
        or not _non_empty_string(value.get("jacsVersion"))
        or not isinstance(signature, dict)
        or signature.get("signatureContentVersion") != "jacs-signature-v2"
        or not _non_empty_string(signature.get("signature"))
        or not _non_empty_string(signer_id)
        or not _non_empty_string(signature.get("agentVersion"))
        or not _non_empty_string(signature.get("publicKeyHash"))
        or not _non_empty_string(signature.get("date"))
    ):
        raise ValueError(
            f"{context} returned incomplete portable v2 signature metadata: "
            "one or more required fields were missing"
        )

    return value


def require_portable_v2_signed_raw(
    raw: Any,
    *,
    context: str = "JACS signer",
) -> str:
    """Return raw JSON only when it contains a complete portable-v2 document."""
    if not _non_empty_string(raw):
        raise ValueError(f"{context} did not return a portable v2 signed document")
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"{context} did not return a JSON portable v2 signed document"
        ) from exc
    require_portable_v2_signed_document(parsed, context=context)
    return raw


__all__ = [
    "require_portable_v2_signed_document",
    "require_portable_v2_signed_raw",
]
