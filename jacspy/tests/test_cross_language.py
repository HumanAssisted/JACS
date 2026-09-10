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
from importlib.metadata import version as package_version
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
ALGORITHMS = ["ed25519", "pq2025", "ed25519_curve"]
PYTHON_FIXTURES = [
    "python_ed25519",
    "python_pq2025",
    "python_ed25519_curve",
]
UPDATE_FIXTURES = os.environ.get("UPDATE_CROSS_LANG_FIXTURES", "").lower() in {
    "1",
    "true",
    "yes",
}
IAT_SKEW_ENV_VAR = "JACS_MAX_IAT_SKEW_SECONDS"
ALLOW_LEGACY_ENV_VAR = "JACS_ALLOW_LEGACY_SIGNATURE_CONTENT"


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


def _is_legacy_v1(signed_json: str) -> bool:
    signature = json.loads(signed_json).get("jacsSignature", {})
    return "signatureContentVersion" not in signature


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


@pytest.fixture(scope="module", autouse=True)
def disable_iat_skew_for_committed_fixtures():
    """Pin snapshot policy and keep legacy verification deny-by-default."""
    previous = os.environ.get(IAT_SKEW_ENV_VAR)
    previous_legacy = os.environ.pop(ALLOW_LEGACY_ENV_VAR, None)
    os.environ[IAT_SKEW_ENV_VAR] = "0"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(IAT_SKEW_ENV_VAR, None)
        else:
            os.environ[IAT_SKEW_ENV_VAR] = previous
        if previous_legacy is not None:
            os.environ[ALLOW_LEGACY_ENV_VAR] = previous_legacy


# ---------------------------------------------------------------------------
# Parametrised verification tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algo", ALGORITHMS)
class TestCrossLanguageVerifyStandalone:
    """Verify Rust-signed fixtures with Python verify_standalone()."""

    def test_verify_fixture_uses_secure_default(self, algo, standalone_cache_dir):
        """V2 verifies normally; legacy v1 is denied without explicit opt-in."""
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
        if _is_legacy_v1(signed_json):
            assert result.valid is False
            assert result.signer_id == ""
        else:
            assert result.valid is True, (
                f"Cross-language verification failed for {algo}: "
                f"signer_id={result.signer_id}, errors={result.errors}"
            )
            assert result.signer_id == metadata["agent_id"]

    def test_legacy_fixture_requires_explicit_compatibility(
        self, algo, standalone_cache_dir, monkeypatch
    ):
        """Explicit compatibility verifies payload but never returns v1 metadata."""
        if not _fixture_exists(algo):
            pytest.skip(f"Fixture {algo} not generated yet")
        signed_json, _metadata = _read_fixture(algo)
        if not _is_legacy_v1(signed_json):
            pytest.skip(f"Fixture {algo} is already v2")

        monkeypatch.setenv(ALLOW_LEGACY_ENV_VAR, "true")
        result = simple.verify_standalone(
            signed_json,
            key_resolution="local",
            data_directory=str(standalone_cache_dir),
            key_directory=str(standalone_cache_dir),
        )

        assert result.valid is True
        assert result.signer_id == ""
        assert result.timestamp == ""

    def test_verify_fixture_metadata_is_only_returned_for_v2(
        self, algo, standalone_cache_dir
    ):
        """Unauthenticated v1 metadata is never returned as trusted output."""
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
        if _is_legacy_v1(signed_json):
            assert result.signer_id == ""
        else:
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

# Produce a Python fixture for the algorithm named by each prefix. The
# `ed25519_curve` alias intentionally resolves to the canonical Ed25519 wire
# algorithm; the pq2025 fixture must contain an actual PQ key and signature.
COUNTERSIGN_ALGO = {
    "ed25519": "ed25519",
    "pq2025": "pq2025",
    "ed25519_curve": "ed25519",
}


class TestCrossLanguageCountersign:
    """Sign the same payload with a truthfully labelled Python agent and export."""

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
            countersigned_doc = json.loads(countersigned_json)
            expected_requested = COUNTERSIGN_ALGO[algo]
            expected_wire = (
                "pq2025" if expected_requested == "pq2025" else "ring-Ed25519"
            )
            assert cs_metadata["algorithm"] == expected_requested
            assert cs_metadata["signing_algorithm"] == expected_wire
            assert (
                countersigned_doc["jacsSignature"]["signingAlgorithm"]
                == expected_wire
            )
            public_key_size = (
                out_dir / f"{out_prefix}_public_key.pem"
            ).stat().st_size
            if expected_wire == "pq2025":
                assert public_key_size == 2592
            else:
                assert public_key_size < 512
            result = simple.verify_standalone(
                countersigned_json,
                key_resolution="local",
                data_directory=str(standalone_cache_dir),
                key_directory=str(standalone_cache_dir),
            )
            assert isinstance(result, VerificationResult)
            if _is_legacy_v1(countersigned_json):
                assert result.valid is False
                previous_legacy = os.environ.get(ALLOW_LEGACY_ENV_VAR)
                os.environ[ALLOW_LEGACY_ENV_VAR] = "true"
                try:
                    result = simple.verify_standalone(
                        countersigned_json,
                        key_resolution="local",
                        data_directory=str(standalone_cache_dir),
                        key_directory=str(standalone_cache_dir),
                    )
                finally:
                    if previous_legacy is None:
                        os.environ.pop(ALLOW_LEGACY_ENV_VAR, None)
                    else:
                        os.environ[ALLOW_LEGACY_ENV_VAR] = previous_legacy
                assert result.valid is True
                assert result.signer_id == ""
                assert result.timestamp == ""
            else:
                assert result.valid is True
                assert result.signer_id == cs_metadata["agent_id"]
            return

        signed_json, metadata = _read_fixture(algo)
        original_doc = json.loads(signed_json)
        payload = original_doc.get("content", {})

        # Create a Python agent in a temp dir and sign the same payload
        password = "CrossLang!Test#99"
        countersign_algo = COUNTERSIGN_ALGO.get(algo, "ed25519")

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
            "jacs_version": package_version("jacs"),
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
