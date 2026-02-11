"""
Cross-language interoperability tests for JACS.

Verifies that documents signed by Rust (via fixture generation) can be verified
by the Python bindings using verify_standalone(). Also tests countersigning:
a Python agent signs the same payload with a different algorithm, and the
countersigned document is exported back to the fixtures directory for Node.js
to consume.

Fixture layout (jacs/tests/fixtures/cross-language/):
    {prefix}_signed.json        -- signed document from Rust
    {prefix}_metadata.json      -- metadata (agent_id, algorithm, etc.)
    {prefix}_public_key.pem     -- raw public key bytes

At runtime, tests build a temporary `public_keys/{hash}.pem` cache from these
committed fixture files so verification is hermetic in CI.

Tests are skipped when the required fixture files do not exist yet.
"""

import json
import os
import pathlib
import tempfile
import pytest

pytest.importorskip("jacs")

from jacs import simple
from jacs.types import VerificationResult


# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

FIXTURES_DIR = (
    pathlib.Path(__file__).parent.parent.parent
    / "jacs"
    / "tests"
    / "fixtures"
    / "cross-language"
)

# Algorithms that the Rust fixture generator creates
ALGORITHMS = ["ed25519", "pq2025"]
PYTHON_FIXTURES = ["python_ed25519", "python_pq2025"]
UPDATE_FIXTURES = os.environ.get("UPDATE_CROSS_LANG_FIXTURES", "").lower() in {
    "1",
    "true",
    "yes",
}


def _fixture_exists(prefix: str) -> bool:
    """Return True when the signed doc and metadata for *prefix* are present."""
    return (
        (FIXTURES_DIR / f"{prefix}_signed.json").exists()
        and (FIXTURES_DIR / f"{prefix}_metadata.json").exists()
        and (FIXTURES_DIR / f"{prefix}_public_key.pem").exists()
    )


def _read_fixture(prefix: str) -> tuple:
    """Return (signed_json_str, metadata_dict) for a fixture prefix."""
    signed = (FIXTURES_DIR / f"{prefix}_signed.json").read_text()
    metadata = json.loads((FIXTURES_DIR / f"{prefix}_metadata.json").read_text())
    return signed, metadata


def _build_standalone_key_cache(cache_dir: pathlib.Path, prefixes: list[str]) -> None:
    """Build a deterministic public_keys cache from committed fixture key files."""
    public_keys_dir = cache_dir / "public_keys"
    public_keys_dir.mkdir(parents=True, exist_ok=True)

    for prefix in prefixes:
        if not _fixture_exists(prefix):
            continue
        _signed, metadata = _read_fixture(prefix)
        key_hash = metadata.get("public_key_hash", "")
        signing_algorithm = metadata.get("signing_algorithm", "")
        raw_key = FIXTURES_DIR / f"{prefix}_public_key.pem"
        if not key_hash or not signing_algorithm or not raw_key.exists():
            continue

        key_bytes = raw_key.read_bytes()
        (public_keys_dir / f"{key_hash}.pem").write_bytes(key_bytes)
        (public_keys_dir / f"{key_hash}.enc_type").write_text(signing_algorithm)


@pytest.fixture(scope="module")
def standalone_cache_dir():
    """Temp key cache for standalone verification (no reliance on ignored fixture caches)."""
    with tempfile.TemporaryDirectory(prefix="jacs_cross_lang_cache_") as td:
        cache_dir = pathlib.Path(td)
        _build_standalone_key_cache(cache_dir, ALGORITHMS + PYTHON_FIXTURES)
        yield cache_dir


# ---------------------------------------------------------------------------
# Parametrised verification tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algo", ALGORITHMS)
class TestCrossLanguageVerifyStandalone:
    """Verify Rust-signed fixtures with Python verify_standalone()."""

    def test_verify_fixture_valid(self, algo, standalone_cache_dir):
        """Rust-signed fixture should verify successfully via Python."""
        if not _fixture_exists(algo):
            pytest.skip(f"Fixture {algo} not generated yet")

        signed_json, metadata = _read_fixture(algo)

        result = simple.verify_standalone(
            signed_json,
            key_resolution="local",
            data_directory=str(standalone_cache_dir),
            key_directory=str(standalone_cache_dir),
        )

        assert isinstance(result, VerificationResult)
        assert result.valid is True, (
            f"Cross-language verification failed for {algo}: "
            f"signer_id={result.signer_id}, errors={result.errors}"
        )
        assert result.signer_id == metadata["agent_id"]

    def test_verify_fixture_extracts_signer_id(self, algo, standalone_cache_dir):
        """verify_standalone() should extract signer_id from the fixture even if verification fails."""
        if not _fixture_exists(algo):
            pytest.skip(f"Fixture {algo} not generated yet")

        signed_json, metadata = _read_fixture(algo)

        result = simple.verify_standalone(
            signed_json,
            key_resolution="local",
            data_directory=str(standalone_cache_dir),
            key_directory=str(standalone_cache_dir),
        )

        assert isinstance(result, VerificationResult)
        assert result.signer_id == metadata["agent_id"]

    def test_fixture_metadata_consistency(self, algo):
        """Metadata and signed document should agree on agent_id and algorithm."""
        if not _fixture_exists(algo):
            pytest.skip(f"Fixture {algo} not generated yet")

        signed_json, metadata = _read_fixture(algo)
        doc = json.loads(signed_json)
        sig = doc.get("jacsSignature", {})

        assert sig.get("agentID") == metadata["agent_id"]
        assert sig.get("signingAlgorithm") == metadata["signing_algorithm"]
        assert sig.get("publicKeyHash") == metadata["public_key_hash"]
        assert metadata["generated_by"] == "rust"

    def test_tampered_fixture_fails(self, algo, standalone_cache_dir):
        """A tampered fixture should fail verification."""
        if not _fixture_exists(algo):
            pytest.skip(f"Fixture {algo} not generated yet")

        signed_json, _metadata = _read_fixture(algo)
        doc = json.loads(signed_json)
        # Tamper with the content
        doc["content"]["test"] = "TAMPERED"
        tampered = json.dumps(doc)

        result = simple.verify_standalone(
            tampered,
            key_resolution="local",
            data_directory=str(standalone_cache_dir),
            key_directory=str(standalone_cache_dir),
        )
        assert result.valid is False

    def test_public_key_file_exists(self, algo, standalone_cache_dir):
        """The public key file and hash-indexed copy should exist."""
        if not _fixture_exists(algo):
            pytest.skip(f"Fixture {algo} not generated yet")

        _signed_json, metadata = _read_fixture(algo)
        pk_hash = metadata["public_key_hash"]

        # Raw key file
        raw_key = FIXTURES_DIR / f"{algo}_public_key.pem"
        assert raw_key.exists(), f"Missing {raw_key}"

        # Hash-indexed key in deterministic standalone cache
        hash_key = standalone_cache_dir / "public_keys" / f"{pk_hash}.pem"
        assert hash_key.exists(), f"Missing {hash_key}"

        enc_type = standalone_cache_dir / "public_keys" / f"{pk_hash}.enc_type"
        assert enc_type.exists(), f"Missing {enc_type}"
        assert enc_type.read_text().strip() == metadata["signing_algorithm"]


# ---------------------------------------------------------------------------
# Countersigning tests
# ---------------------------------------------------------------------------

# The countersign algorithm is deliberately different from the fixture algo.
COUNTERSIGN_ALGO = {
    "ed25519": "ring-Ed25519",
    "pq2025": "ring-Ed25519",
}


class TestCrossLanguageCountersign:
    """Sign the same payload with a Python agent (different algo) and export."""

    @pytest.mark.parametrize("algo", ALGORITHMS)
    def test_countersign_and_export(self, algo, tmp_path, standalone_cache_dir):
        """Countersign fixture payload with a Python agent and write to fixtures."""
        if not _fixture_exists(algo):
            pytest.skip(f"Fixture {algo} not generated yet")

        out_prefix = f"python_{algo}"
        out_dir = FIXTURES_DIR

        if not UPDATE_FIXTURES:
            if not _fixture_exists(out_prefix):
                pytest.skip(
                    "Python countersigned fixtures missing. "
                    "Set UPDATE_CROSS_LANG_FIXTURES=1 to regenerate."
                )

            countersigned_json, cs_metadata = _read_fixture(out_prefix)
            result = simple.verify_standalone(
                countersigned_json,
                key_resolution="local",
                data_directory=str(standalone_cache_dir),
                key_directory=str(standalone_cache_dir),
            )
            assert isinstance(result, VerificationResult)
            assert result.valid is True
            assert result.signer_id == cs_metadata["agent_id"]
            return

        signed_json, metadata = _read_fixture(algo)
        original_doc = json.loads(signed_json)
        payload = original_doc.get("content", {})

        # Create a Python agent in a temp dir and sign the same payload
        password = "CrossLang!Test#99"
        countersign_algo = COUNTERSIGN_ALGO.get(algo, "ring-Ed25519")

        original_cwd = os.getcwd()
        prev_pw = os.environ.get("JACS_PRIVATE_KEY_PASSWORD")
        os.environ["JACS_PRIVATE_KEY_PASSWORD"] = password
        try:
            os.chdir(tmp_path)
            agent_info = simple.create(
                name=f"python-countersign-{algo}",
                password=password,
                algorithm=countersign_algo,
                data_directory="jacs_data",
                key_directory="jacs_keys",
                config_path="jacs.config.json",
            )

            countersigned = simple.sign_message(payload)
            assert countersigned.document_id
            assert countersigned.signer_id == agent_info.agent_id

            # Read the Python agent's public key
            pub_key_bytes = (tmp_path / "jacs_keys" / "jacs.public.pem").read_bytes()
        finally:
            os.chdir(original_cwd)
            simple.reset()
            if prev_pw is None:
                os.environ.pop("JACS_PRIVATE_KEY_PASSWORD", None)
            else:
                os.environ["JACS_PRIVATE_KEY_PASSWORD"] = prev_pw

        # Write countersigned doc to fixtures for Node.js
        (out_dir / f"{out_prefix}_signed.json").write_text(countersigned.raw_json)
        (out_dir / f"{out_prefix}_public_key.pem").write_bytes(pub_key_bytes)

        # Extract hash and write hash-indexed key
        cs_doc = json.loads(countersigned.raw_json)
        cs_sig = cs_doc.get("jacsSignature", {})
        cs_hash = cs_sig.get("publicKeyHash", "")
        cs_signing_algo = cs_sig.get("signingAlgorithm", "")

        if cs_hash:
            pk_dir = out_dir / "public_keys"
            pk_dir.mkdir(exist_ok=True)
            (pk_dir / f"{cs_hash}.pem").write_bytes(pub_key_bytes)
            (pk_dir / f"{cs_hash}.enc_type").write_text(cs_signing_algo)

        # Write metadata
        cs_metadata = {
            "algorithm": countersign_algo,
            "signing_algorithm": cs_signing_algo,
            "agent_id": agent_info.agent_id,
            "document_id": countersigned.document_id,
            "timestamp": countersigned.signed_at,
            "public_key_hash": cs_hash,
            "generated_by": "python",
            "jacs_version": "0.8.0",
            "original_fixture": algo,
        }
        (out_dir / f"{out_prefix}_metadata.json").write_text(
            json.dumps(cs_metadata, indent=2)
        )

        # Verify the countersigned document standalone
        result = simple.verify_standalone(
            countersigned.raw_json,
            key_resolution="local",
            data_directory=str(out_dir),
            key_directory=str(out_dir),
        )
        assert isinstance(result, VerificationResult)
        assert result.valid is True, (
            f"Countersigned doc verification failed for {algo}: errors={result.errors}"
        )
        assert result.signer_id == agent_info.agent_id
