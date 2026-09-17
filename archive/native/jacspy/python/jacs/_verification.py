"""Fail-closed helpers for presenting verification results.

Cryptographic legacy-v1 compatibility authenticates document payload fields,
but not the signer, key, or time fields stored under ``jacsSignature``. Keep
that distinction in one place so every high-level Python API presents the same
attribution contract.
"""

from typing import Any, Mapping


V2_SIGNATURE_CONTENT_VERSION = "jacs-signature-v2"


def authenticated_signature_metadata(
    document: Mapping[str, Any] | None,
    *,
    verified: bool,
) -> tuple[str, str, str]:
    """Return attribution only for a literally valid v2 verification result.

    A v2-shaped envelope does not authenticate itself. Callers must supply the
    native verifier's result so invalid documents can never promote parsed
    signer, key, or timestamp fields into trusted high-level output.
    """
    if verified is not True:
        return "", "", ""
    if not isinstance(document, Mapping):
        return "", "", ""
    signature = document.get("jacsSignature")
    if not isinstance(signature, Mapping):
        return "", "", ""
    if signature.get("signatureContentVersion") != V2_SIGNATURE_CONTENT_VERSION:
        return "", "", ""

    signer_id = signature.get("agentId", signature.get("agentID", ""))
    public_key_hash = signature.get("publicKeyHash", "")
    timestamp = signature.get("date", "")
    return (
        signer_id if isinstance(signer_id, str) else "",
        public_key_hash if isinstance(public_key_hash, str) else "",
        timestamp if isinstance(timestamp, str) else "",
    )


def normalize_attestation_verification_result(result: Any) -> dict[str, Any]:
    """Normalize an attestation result without trusting JSON truthiness.

    The native result is an authenticated output contract. A missing or
    non-boolean security flag therefore cannot be treated as success. The
    aggregate result is additionally ANDed with every nested cryptographic,
    evidence, and chain flag so contradictory native output fails closed.
    """
    if not isinstance(result, Mapping):
        raise ValueError("attestation verification result must be a JSON object")

    normalized = dict(result)

    raw_crypto = result.get("crypto")
    crypto = dict(raw_crypto) if isinstance(raw_crypto, Mapping) else {}
    crypto["signatureValid"] = crypto.get("signatureValid") is True
    crypto["hashValid"] = crypto.get("hashValid") is True
    normalized["crypto"] = crypto
    crypto_valid = crypto["signatureValid"] and crypto["hashValid"]

    raw_evidence = result.get("evidence")
    evidence_well_formed = isinstance(raw_evidence, list)
    evidence = []
    if evidence_well_formed:
        for item in raw_evidence:
            entry = dict(item) if isinstance(item, Mapping) else {}
            entry["digestValid"] = entry.get("digestValid") is True
            entry["freshnessValid"] = entry.get("freshnessValid") is True
            evidence.append(entry)
    normalized["evidence"] = evidence
    evidence_valid = evidence_well_formed and all(
        item["digestValid"] and item["freshnessValid"] for item in evidence
    )

    raw_chain = result.get("chain")
    if raw_chain is None:
        normalized["chain"] = None
        chain_valid = True
    else:
        chain = dict(raw_chain) if isinstance(raw_chain, Mapping) else {}
        raw_links = chain.get("links")
        links_well_formed = isinstance(raw_links, list)
        links = []
        if links_well_formed:
            for item in raw_links:
                link = dict(item) if isinstance(item, Mapping) else {}
                link["valid"] = link.get("valid") is True
                links.append(link)
        chain["links"] = links
        chain["valid"] = (
            chain.get("valid") is True
            and links_well_formed
            and all(link["valid"] for link in links)
        )
        normalized["chain"] = chain
        chain_valid = chain["valid"]

    normalized["valid"] = (
        result.get("valid") is True and crypto_valid and evidence_valid and chain_valid
    )
    return normalized
