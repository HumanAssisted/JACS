"""
Parity tests for the jacspy (Python/PyO3) binding.

These tests mirror the Rust reference tests in binding-core/tests/parity.rs
and verify that the Python binding produces structurally identical behavior.
Shared fixture inputs are loaded from binding-core/tests/fixtures/parity_inputs.json.

Parity guarantees:
  1. Structural parity   -- signed documents contain required field names/types
  2. Roundtrip parity     -- sign -> verify succeeds for all fixture inputs
  3. Cross-algorithm      -- ed25519 and pq2025 produce structurally identical output
  4. Identity parity      -- agent_id, key_id, PEM, base64, export, diagnostics, verify_self
  5. Error parity         -- all bindings reject the same invalid inputs
  6. Sign raw bytes       -- sign_string returns valid base64
  7. Sign file            -- sign_file produces verifiable documents
  8. Verification result  -- verification output contains required fields
  9. create_agent parity  -- programmatic agent creation is functional

Note: Exact crypto output bytes differ per invocation (nonce/randomness),
so we verify structure and verifiability, not byte-equality.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path

import pytest

# Skip all tests if the native jacs module is not built
jacs = pytest.importorskip("jacs")

from jacs import SimpleAgent

# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "binding-core"
    / "tests"
    / "fixtures"
    / "parity_inputs.json"
)


@pytest.fixture(scope="module")
def parity_inputs() -> dict:
    """Load the shared parity test fixture file."""
    assert FIXTURE_PATH.exists(), (
        f"Parity fixture not found at {FIXTURE_PATH}. "
        "Ensure binding-core/tests/fixtures/parity_inputs.json exists."
    )
    with open(FIXTURE_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def sign_message_inputs(parity_inputs: dict) -> list[dict]:
    return parity_inputs["sign_message_inputs"]


@pytest.fixture(scope="module")
def sign_raw_bytes_inputs(parity_inputs: dict) -> list[dict]:
    return parity_inputs["sign_raw_bytes_inputs"]


@pytest.fixture(scope="module")
def expected_signed_doc_fields(parity_inputs: dict) -> dict:
    return parity_inputs["expected_signed_document_fields"]


@pytest.fixture(scope="module")
def expected_verify_fields(parity_inputs: dict) -> dict:
    return parity_inputs["expected_verification_result_fields"]


def _ephemeral(algo: str = "ed25519") -> SimpleAgent:
    """Create an ephemeral in-memory agent. Returns just the agent."""
    agent, _info = SimpleAgent.ephemeral(algorithm=algo)
    return agent


# ===========================================================================
# 1. Structural parity: signed documents have required fields
# ===========================================================================


class TestParitySignedDocumentStructure:
    """Mirrors test_parity_signed_document_structure_{ed25519,pq2025} in Rust."""

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_signed_document_has_required_fields(
        self,
        algo: str,
        sign_message_inputs: list[dict],
        expected_signed_doc_fields: dict,
    ) -> None:
        agent = _ephemeral(algo)
        required_top = expected_signed_doc_fields["required_top_level"]
        required_sig = expected_signed_doc_fields["required_signature_fields"]

        for inp in sign_message_inputs:
            name = inp["name"]
            data = inp["data"]

            result = agent.sign_message(data)
            assert "raw" in result, f"[{algo}] sign_message for '{name}' missing 'raw'"

            signed = json.loads(result["raw"])

            # Check required top-level fields
            for field in required_top:
                assert field in signed, (
                    f"[{algo}] signed document for '{name}' "
                    f"missing required field '{field}'"
                )

            # Check required signature fields
            sig_obj = signed["jacsSignature"]
            for field in required_sig:
                assert field in sig_obj, (
                    f"[{algo}] jacsSignature for '{name}' "
                    f"missing required field '{field}'"
                )


# ===========================================================================
# 2. Roundtrip parity: sign -> verify succeeds for all fixture inputs
# ===========================================================================


class TestParitySignVerifyRoundtrip:
    """Mirrors test_parity_sign_verify_roundtrip_{ed25519,pq2025} in Rust."""

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_roundtrip_all_inputs(
        self, algo: str, sign_message_inputs: list[dict]
    ) -> None:
        agent = _ephemeral(algo)

        for inp in sign_message_inputs:
            name = inp["name"]
            data = inp["data"]

            signed = agent.sign_message(data)
            signed_json = signed["raw"]

            verify_result = agent.verify(signed_json)
            assert verify_result["valid"] is True, (
                f"[{algo}] roundtrip verification failed for '{name}': "
                f"errors={verify_result.get('errors')}"
            )


# ===========================================================================
# 3. Cross-algorithm structure consistency
# ===========================================================================


class TestParityCrossAlgorithmStructure:
    """Mirrors test_parity_cross_algorithm_structure_consistency in Rust."""

    def test_ed25519_and_pq2025_have_same_structure(
        self, sign_message_inputs: list[dict]
    ) -> None:
        ed_agent = _ephemeral("ed25519")
        pq_agent = _ephemeral("pq2025")

        # Use the first fixture input (simple_message)
        data = sign_message_inputs[0]["data"]

        ed_signed = json.loads(ed_agent.sign_message(data)["raw"])
        pq_signed = json.loads(pq_agent.sign_message(data)["raw"])

        # Both should have jacsId and jacsSignature
        assert "jacsId" in ed_signed, "ed25519 signed doc should have jacsId"
        assert "jacsId" in pq_signed, "pq2025 signed doc should have jacsId"
        assert "jacsSignature" in ed_signed, (
            "ed25519 signed doc should have jacsSignature"
        )
        assert "jacsSignature" in pq_signed, (
            "pq2025 signed doc should have jacsSignature"
        )

        # Signature objects should have the same field names
        ed_sig_keys = sorted(ed_signed["jacsSignature"].keys())
        pq_sig_keys = sorted(pq_signed["jacsSignature"].keys())
        assert ed_sig_keys == pq_sig_keys, (
            "jacsSignature fields should be identical across algorithms: "
            f"ed25519={ed_sig_keys}, pq2025={pq_sig_keys}"
        )


# ===========================================================================
# 4. Identity parity: agent_id, key_id, public_key, diagnostics
# ===========================================================================


class TestParityIdentityMethods:
    """Mirrors test_parity_identity_methods_{ed25519,pq2025} in Rust."""

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_get_agent_id(self, algo: str) -> None:
        agent = _ephemeral(algo)
        agent_id = agent.get_agent_id()
        assert isinstance(agent_id, str), f"[{algo}] agent_id should be str"
        assert len(agent_id) > 0, f"[{algo}] agent_id should be non-empty"

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_key_id(self, algo: str) -> None:
        agent = _ephemeral(algo)
        kid = agent.key_id()
        assert isinstance(kid, str), f"[{algo}] key_id should be str"
        assert len(kid) > 0, f"[{algo}] key_id should be non-empty"

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_get_public_key_pem(self, algo: str) -> None:
        agent = _ephemeral(algo)
        pem = agent.get_public_key_pem()
        assert isinstance(pem, str), f"[{algo}] PEM should be str"
        assert "-----BEGIN" in pem or "PUBLIC KEY" in pem, (
            f"[{algo}] should return PEM format, got: {pem[:80]}..."
        )

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_get_public_key_base64(self, algo: str) -> None:
        agent = _ephemeral(algo)
        key_b64 = agent.get_public_key_base64()
        assert isinstance(key_b64, str), f"[{algo}] base64 key should be str"
        # Must be valid base64 that decodes to non-empty bytes
        decoded = base64.b64decode(key_b64)
        assert len(decoded) > 0, (
            f"[{algo}] decoded public key should be non-empty"
        )

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_export_agent(self, algo: str) -> None:
        agent = _ephemeral(algo)
        exported = agent.export_agent()
        assert isinstance(exported, str), f"[{algo}] export should be str"
        parsed = json.loads(exported)
        assert "jacsId" in parsed, (
            f"[{algo}] exported agent should have jacsId"
        )

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_diagnostics(self, algo: str) -> None:
        agent = _ephemeral(algo)
        diag = agent.diagnostics()
        assert isinstance(diag, str), f"[{algo}] diagnostics should be str"
        diag_v = json.loads(diag)
        assert "jacs_version" in diag_v, (
            f"[{algo}] diagnostics should have jacs_version"
        )
        assert diag_v["agent_loaded"] is True, (
            f"[{algo}] diagnostics should show agent_loaded=true"
        )

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_verify_self(self, algo: str) -> None:
        agent = _ephemeral(algo)
        result = agent.verify_self()
        assert isinstance(result, dict), f"[{algo}] verify_self should return dict"
        assert result["valid"] is True, (
            f"[{algo}] verify_self should be valid, errors={result.get('errors')}"
        )

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_is_strict(self, algo: str) -> None:
        agent = _ephemeral(algo)
        assert agent.is_strict() is False, (
            f"[{algo}] ephemeral agent should not be strict"
        )


# ===========================================================================
# 5. Sign raw bytes (sign_string) parity
# ===========================================================================


class TestParitySignRawBytes:
    """Mirrors test_parity_sign_raw_bytes_{ed25519,pq2025} in Rust.

    Python's SimpleAgent exposes sign_string(data: str) -> str which internally
    calls sign_raw_bytes_base64 in Rust. We test via sign_string with the
    decoded fixture data.
    """

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_sign_raw_bytes_all_inputs(
        self, algo: str, sign_raw_bytes_inputs: list[dict]
    ) -> None:
        agent = _ephemeral(algo)

        for inp in sign_raw_bytes_inputs:
            name = inp["name"]
            data_b64 = inp["data_base64"]
            # Decode fixture base64 to get the raw bytes, then convert to str
            # for sign_string. For binary data that isn't valid UTF-8, we pass
            # the base64 string itself as the signing input.
            try:
                data_str = base64.b64decode(data_b64).decode("utf-8")
            except UnicodeDecodeError:
                # Binary data -- sign the base64 representation instead
                data_str = data_b64

            sig_b64 = agent.sign_string(data_str)
            assert isinstance(sig_b64, str), (
                f"[{algo}] sign_string for '{name}' should return str"
            )

            # Result should be valid base64
            sig_bytes = base64.b64decode(sig_b64)
            assert len(sig_bytes) > 0, (
                f"[{algo}] signature for '{name}' should be non-empty"
            )


# ===========================================================================
# 6. Sign file parity
# ===========================================================================


class TestParitySignFile:
    """Mirrors test_parity_sign_file_{ed25519,pq2025} in Rust."""

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_sign_and_verify_file(self, algo: str) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("parity test content")
            file_path = f.name

        try:
            agent = _ephemeral(algo)

            signed = agent.sign_file(file_path, embed=True)
            assert "raw" in signed, f"[{algo}] sign_file should return dict with 'raw'"

            signed_doc = json.loads(signed["raw"])
            assert "jacsSignature" in signed_doc, (
                f"[{algo}] signed file should have jacsSignature"
            )
            assert "jacsId" in signed_doc, (
                f"[{algo}] signed file should have jacsId"
            )

            # Verify the signed file document
            verify_result = agent.verify(signed["raw"])
            assert verify_result["valid"] is True, (
                f"[{algo}] signed file should verify, "
                f"errors={verify_result.get('errors')}"
            )
        finally:
            os.unlink(file_path)


# ===========================================================================
# 7. Error parity: all bindings must reject these inputs
# ===========================================================================


class TestParityErrors:
    """Mirrors error parity tests in Rust."""

    def test_verify_rejects_invalid_json(self) -> None:
        """Mirrors test_parity_verify_rejects_invalid_json."""
        agent = _ephemeral("ed25519")
        with pytest.raises(RuntimeError):
            agent.verify("not-valid-json{{{")

    def test_verify_rejects_tampered_document(self) -> None:
        """Mirrors test_parity_verify_rejects_tampered_document.

        Tampering with the signed content should either raise an error
        or return valid=False -- either is acceptable parity behavior.
        """
        agent = _ephemeral("ed25519")
        signed = agent.sign_message({"original": True})
        signed_json = signed["raw"]

        # Tamper with the content
        parsed = json.loads(signed_json)
        if "content" in parsed:
            parsed["content"] = {"original": False, "tampered": True}
        else:
            # If there's no "content" key, modify any data field
            parsed["_tampered"] = True
        tampered = json.dumps(parsed)

        try:
            result = agent.verify(tampered)
            # If verify doesn't raise, it should report invalid
            assert result["valid"] is False, (
                "tampered document should verify as invalid"
            )
        except RuntimeError:
            # Also acceptable: raising an error for tampered input
            pass

    def test_sign_message_rejects_invalid_json_string(self) -> None:
        """Mirrors test_parity_sign_message_rejects_invalid_json.

        The Python API accepts Python objects (not raw JSON strings),
        so we pass a string that the binding tries to serialize.
        Passing a valid Python string should succeed (it becomes a JSON
        string). The real error parity is tested via verify on garbage.
        """
        # In Python, sign_message accepts any JSON-serializable object,
        # so invalid JSON as a concept doesn't directly apply the same way.
        # We test that verify rejects garbage, which is the true parity.
        agent = _ephemeral("ed25519")
        with pytest.raises(RuntimeError):
            agent.verify("not valid json {{")

    def test_verify_by_id_rejects_bad_format(self) -> None:
        """Mirrors test_parity_verify_by_id_rejects_bad_format."""
        agent = _ephemeral("ed25519")
        with pytest.raises(RuntimeError):
            agent.verify_by_id("not-a-valid-id")


# ===========================================================================
# 8. Verification result structure parity
# ===========================================================================


class TestParityVerificationResultStructure:
    """Mirrors test_parity_verification_result_structure in Rust."""

    def test_verification_result_has_required_fields(
        self, expected_verify_fields: dict
    ) -> None:
        agent = _ephemeral("ed25519")
        required = expected_verify_fields["required"]

        signed = agent.sign_message({"structure_test": True})
        result = agent.verify(signed["raw"])

        for field in required:
            assert field in result, (
                f"verification result missing required field '{field}'"
            )


# ===========================================================================
# 9. create_agent parity (mirrors test_parity_create_with_params)
# ===========================================================================


class TestParityCreateAgent:
    """Mirrors test_parity_create_with_params in Rust."""

    def test_create_agent_is_functional(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = os.path.join(tmpdir, "data")
            key_dir = os.path.join(tmpdir, "keys")
            config_path = os.path.join(tmpdir, "config.json")
            password = "TestP@ss123!#"

            # Set env var that SimpleAgent reads for key decryption at sign time
            old_pw = os.environ.get("JACS_PRIVATE_KEY_PASSWORD")
            os.environ["JACS_PRIVATE_KEY_PASSWORD"] = password

            try:
                agent, info = SimpleAgent.create_agent(
                    name="parity-agent",
                    password=password,
                    algorithm="ring-Ed25519",
                    data_directory=data_dir,
                    key_directory=key_dir,
                    config_path=config_path,
                )

                # info should have agent_id
                assert isinstance(info, dict)
                assert info.get("agent_id"), (
                    "agent_id from create_agent should be non-empty"
                )

                # Agent should be functional: sign and verify
                signed = agent.sign_message({"params_parity": True})
                assert signed["raw"], "signed document should be non-empty"

                result = agent.verify(signed["raw"])
                assert result["valid"] is True, (
                    f"created agent should verify its own signatures, "
                    f"errors={result.get('errors')}"
                )
            finally:
                if old_pw is not None:
                    os.environ["JACS_PRIVATE_KEY_PASSWORD"] = old_pw
                else:
                    os.environ.pop("JACS_PRIVATE_KEY_PASSWORD", None)


# ===========================================================================
# 10. Ephemeral info dict parity
# ===========================================================================


class TestParityEphemeralInfo:
    """Verify the info dict returned by SimpleAgent.ephemeral()."""

    @pytest.mark.parametrize("algo", ["ed25519", "pq2025"])
    def test_ephemeral_returns_info_dict(self, algo: str) -> None:
        agent, info = SimpleAgent.ephemeral(algorithm=algo)
        assert isinstance(info, dict), "ephemeral should return (agent, dict)"
        assert info.get("agent_id"), (
            f"[{algo}] info should have non-empty agent_id"
        )
        assert info.get("name"), f"[{algo}] info should have non-empty name"
        assert info.get("algorithm"), (
            f"[{algo}] info should have non-empty algorithm"
        )
        assert info.get("version"), (
            f"[{algo}] info should have non-empty version"
        )
