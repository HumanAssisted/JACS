"""Tests for attestation bindings in jacspy.

These tests exercise the attestation API surface exposed through:
  - SimpleAgent (PyO3) create_attestation / verify_attestation / lift_to_attestation
  - JacsClient (pure Python) convenience methods

Tests are skipped when the native module was built without the 'attestation' feature.
"""

import json

import pytest

# ---- Feature gate: skip the whole module when attestation is not compiled ----
try:
    from jacs import SimpleAgent as _SimpleAgent

    _agent, _ = _SimpleAgent.ephemeral("ed25519")
    _agent.create_attestation  # attribute check
    _HAS_ATTESTATION = True
except (ImportError, AttributeError):
    _HAS_ATTESTATION = False

pytestmark = pytest.mark.skipif(
    not _HAS_ATTESTATION,
    reason="Attestation feature not compiled into native module",
)

from jacs.client import JacsClient
from jacs.types import SignedDocument
from conftest import TEST_ALGORITHM


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_subject():
    return {
        "type": "artifact",
        "id": "test-artifact-001",
        "digests": {"sha256": "abc123def456"},
    }


def _make_claims():
    return [
        {
            "name": "reviewed",
            "value": True,
            "confidence": 0.95,
            "assuranceLevel": "verified",
        }
    ]


# ===========================================================================
# SimpleAgent-level tests (PyO3 methods)
# ===========================================================================


class TestSimpleAgentAttestation:
    """Tests for the PyO3 SimpleAgent attestation methods."""

    def test_create_attestation_basic(self):
        """Create an attestation with subject + claims, returns JSON with attestation key."""
        agent, _ = _SimpleAgent.ephemeral("ed25519")
        params = {"subject": _make_subject(), "claims": _make_claims()}
        result = agent.create_attestation(json.dumps(params))

        assert isinstance(result, str)
        doc = json.loads(result)
        assert "attestation" in doc
        assert doc["attestation"]["subject"]["id"] == "test-artifact-001"

    def test_verify_attestation_local(self):
        """Create then verify (local tier). Result should be valid."""
        agent, _ = _SimpleAgent.ephemeral("ed25519")
        params = {"subject": _make_subject(), "claims": _make_claims()}
        raw = agent.create_attestation(json.dumps(params))
        doc = json.loads(raw)
        doc_key = f"{doc['jacsId']}:{doc['jacsVersion']}"

        result_json = agent.verify_attestation(doc_key)
        result = json.loads(result_json)
        assert result["valid"] is True
        assert result["crypto"]["signatureValid"] is True
        assert result["crypto"]["hashValid"] is True

    def test_verify_attestation_full(self):
        """Create then full-verify. Evidence list should be present."""
        agent, _ = _SimpleAgent.ephemeral("ed25519")
        params = {"subject": _make_subject(), "claims": _make_claims()}
        raw = agent.create_attestation(json.dumps(params))
        doc = json.loads(raw)
        doc_key = f"{doc['jacsId']}:{doc['jacsVersion']}"

        result_json = agent.verify_attestation_full(doc_key)
        result = json.loads(result_json)
        assert result["valid"] is True
        assert isinstance(result["evidence"], list)

    def test_lift_to_attestation(self):
        """Sign a message then lift to attestation."""
        agent, _ = _SimpleAgent.ephemeral("ed25519")
        signed = agent.sign_message({"content": "Original document"})
        signed_raw = signed["raw"]

        claims_json = json.dumps(_make_claims())
        att_raw = agent.lift_to_attestation(signed_raw, claims_json)
        att_doc = json.loads(att_raw)
        assert "attestation" in att_doc
        assert att_doc["attestation"]["subject"]["id"] == signed["document_id"]

    def test_create_attestation_invalid_claims(self):
        """Empty claims should raise."""
        agent, _ = _SimpleAgent.ephemeral("ed25519")
        params = {"subject": _make_subject(), "claims": []}
        with pytest.raises(RuntimeError):
            agent.create_attestation(json.dumps(params))

    def test_export_dsse(self):
        """Export DSSE envelope from a created attestation."""
        agent, _ = _SimpleAgent.ephemeral("ed25519")
        params = {"subject": _make_subject(), "claims": _make_claims()}
        raw = agent.create_attestation(json.dumps(params))

        dsse_json = agent.export_dsse(raw)
        envelope = json.loads(dsse_json)
        assert "payloadType" in envelope
        assert envelope["payloadType"] == "application/vnd.in-toto+json"
        assert "signatures" in envelope


# ===========================================================================
# JacsClient-level tests (pure Python convenience)
# ===========================================================================


class TestJacsClientAttestation:
    """Tests for the JacsClient attestation convenience methods."""

    def test_client_create_attestation(self):
        """Create attestation via JacsClient. Should return SignedDocument."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        signed = client.create_attestation(
            subject=_make_subject(),
            claims=_make_claims(),
        )
        assert isinstance(signed, SignedDocument)
        assert signed.document_id
        doc = json.loads(signed.raw_json)
        assert "attestation" in doc

    def test_client_verify_attestation(self):
        """Verify attestation via JacsClient (local tier)."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        signed = client.create_attestation(
            subject=_make_subject(),
            claims=_make_claims(),
        )
        result = client.verify_attestation(signed.raw_json)
        assert isinstance(result, dict)
        assert result["valid"] is True

    def test_client_verify_attestation_full(self):
        """Verify attestation via JacsClient (full tier)."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        signed = client.create_attestation(
            subject=_make_subject(),
            claims=_make_claims(),
        )
        result = client.verify_attestation(signed.raw_json, full=True)
        assert isinstance(result, dict)
        assert result["valid"] is True
        assert isinstance(result.get("evidence"), list)

    def test_client_lift_to_attestation(self):
        """Lift a signed document to attestation via JacsClient."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        signed_msg = client.sign_message({"content": "lift me"})
        att = client.lift_to_attestation(signed_msg, _make_claims())
        assert isinstance(att, SignedDocument)
        doc = json.loads(att.raw_json)
        assert "attestation" in doc

    def test_attestation_round_trip(self):
        """Create, verify local, verify full -- full round trip."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        signed = client.create_attestation(
            subject=_make_subject(),
            claims=_make_claims(),
        )
        local_result = client.verify_attestation(signed.raw_json, full=False)
        assert local_result["valid"] is True

        full_result = client.verify_attestation(signed.raw_json, full=True)
        assert full_result["valid"] is True

    def test_client_export_dsse(self):
        """Export DSSE via JacsClient."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        signed = client.create_attestation(
            subject=_make_subject(),
            claims=_make_claims(),
        )
        envelope = client.export_attestation_dsse(signed.raw_json)
        assert isinstance(envelope, dict)
        assert envelope["payloadType"] == "application/vnd.in-toto+json"
        assert len(envelope.get("signatures", [])) > 0

    def test_client_create_invalid_claims_raises(self):
        """Empty claims should raise via JacsClient."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        with pytest.raises(Exception):
            client.create_attestation(subject=_make_subject(), claims=[])

    def test_client_verify_attestation_nonstrict_returns_invalid(self):
        """Non-strict client returns valid=False on bad input instead of raising."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM, strict=False)
        result = client.verify_attestation('{"jacsId":"fake","jacsVersion":"v1"}')
        assert result["valid"] is False
        assert len(result.get("errors", [])) > 0

    def test_client_create_with_policy_context(self):
        """Create attestation with policy context."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        signed = client.create_attestation(
            subject=_make_subject(),
            claims=_make_claims(),
            policy_context={
                "policyId": "policy-001",
                "requiredTrustLevel": "verified",
            },
        )
        doc = json.loads(signed.raw_json)
        assert doc["attestation"]["policyContext"]["policyId"] == "policy-001"
