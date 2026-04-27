"""Cross-language provenance tests (Task 13, PRD §5.1 / §5.2).

Verifies that text + image fixtures signed by Rust under
``jacs/tests/fixtures/provenance/`` are accepted by the Python bindings,
and that a Python-signed file round-trips through the Rust ``jacs verify-text``
CLI.

Run from the repo root::

    pytest jacspy/tests/test_cross_language_provenance.py -v

Fixtures are committed; regenerate with::

    UPDATE_PROVENANCE_FIXTURES=1 cargo test -p jacs --test provenance_cross_language_tests \\
        -- --ignored regenerate_provenance_fixtures

These tests are skipped when fixtures are absent (e.g. fresh checkout that
hasn't run the regenerator).
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess

import pytest

jacs = pytest.importorskip("jacs")

from jacs import JacsClient, MissingSignatureError  # noqa: E402

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

FIXTURES_DIR = (
    pathlib.Path(__file__).parent.parent.parent
    / "jacs"
    / "tests"
    / "fixtures"
    / "provenance"
)
KEYS_DIR = FIXTURES_DIR / "keys"
METADATA_PATH = FIXTURES_DIR / "metadata.json"


def _fixtures_present() -> bool:
    return METADATA_PATH.exists() and KEYS_DIR.exists()


def _read_metadata() -> dict:
    return json.loads(METADATA_PATH.read_text())


pytestmark = pytest.mark.skipif(
    not _fixtures_present(),
    reason=(
        "Provenance fixtures not generated. "
        "Run UPDATE_PROVENANCE_FIXTURES=1 cargo test -p jacs --test "
        "provenance_cross_language_tests -- --ignored regenerate_provenance_fixtures"
    ),
)


@pytest.fixture(scope="module")
def fixture_metadata():
    return _read_metadata()


@pytest.fixture
def verifier():
    """Ephemeral Python JacsClient (different identity from any signer)."""
    client = JacsClient.ephemeral()
    yield client
    client.reset()


# ---------------------------------------------------------------------------
# Acceptance #2 — Python verifies all four Rust-signed media types.
# ---------------------------------------------------------------------------


def test_python_verifies_rust_signed_md_ed25519(verifier, fixture_metadata):
    path = FIXTURES_DIR / "rust_signed_ed25519.md"
    assert path.exists()
    result = verifier.verify_text(str(path), key_dir=str(KEYS_DIR))
    assert result.status == "signed"
    assert len(result.signatures) == 1
    entry = result.signatures[0]
    assert entry.status == "valid"
    assert entry.algorithm == "ed25519"
    assert entry.signer_id == fixture_metadata["agent_ed25519"]["agent_id"]


def test_python_verifies_rust_signed_md_pq2025(verifier, fixture_metadata):
    path = FIXTURES_DIR / "rust_signed_pq2025.md"
    assert path.exists()
    result = verifier.verify_text(str(path), key_dir=str(KEYS_DIR))
    assert result.status == "signed"
    assert len(result.signatures) == 1
    entry = result.signatures[0]
    assert entry.status == "valid"
    assert entry.algorithm == "pq2025"
    assert entry.signer_id == fixture_metadata["agent_pq2025"]["agent_id"]


def test_python_verifies_rust_signed_md_multi_algo(verifier, fixture_metadata):
    """The headline cross-language assertion: an unordered, mixed-algorithm
    file produced by Rust verifies fully in Python."""
    path = FIXTURES_DIR / "rust_signed_multi_algo.md"
    assert path.exists()
    result = verifier.verify_text(str(path), key_dir=str(KEYS_DIR))
    assert result.status == "signed"
    assert len(result.signatures) == 2

    statuses = {s.status for s in result.signatures}
    assert statuses == {"valid"}, f"unexpected statuses: {statuses}"

    algos = sorted(s.algorithm for s in result.signatures)
    assert algos == ["ed25519", "pq2025"]


def test_python_verifies_rust_signed_png(verifier):
    path = FIXTURES_DIR / "rust_signed_ed25519.png"
    assert path.exists()
    result = verifier.verify_image(str(path), key_dir=str(KEYS_DIR))
    assert result.status == "valid"
    assert result.format == "png"


def test_python_verifies_rust_signed_jpeg(verifier):
    path = FIXTURES_DIR / "rust_signed_ed25519.jpg"
    assert path.exists()
    result = verifier.verify_image(str(path), key_dir=str(KEYS_DIR))
    assert result.status == "valid"
    assert result.format == "jpeg"


def test_python_verifies_rust_signed_webp(verifier):
    path = FIXTURES_DIR / "rust_signed_ed25519.webp"
    assert path.exists()
    result = verifier.verify_image(str(path), key_dir=str(KEYS_DIR))
    assert result.status == "valid"
    assert result.format == "webp"


# ---------------------------------------------------------------------------
# C3 — Rust-signed markdown signature block body parses as native YAML.
# ---------------------------------------------------------------------------


def test_python_yaml_parses_rust_signed_block_body():
    yaml = pytest.importorskip("yaml")

    content = (FIXTURES_DIR / "rust_signed_ed25519.md").read_text()
    begin = "-----BEGIN JACS SIGNATURE-----\n"
    end_marker = "\n-----END JACS SIGNATURE-----"
    start = content.index(begin) + len(begin)
    end = content.index(end_marker)
    parsed = yaml.safe_load(content[start:end])

    # camelCase fields are mandated by the YAML schema (PRD §3.1 / §4.1.2).
    for key in ("signer", "signedContentHash", "publicKeyHash", "algorithm", "signature"):
        assert key in parsed, f"missing {key} in YAML body"


# ---------------------------------------------------------------------------
# C1 — strict + permissive parity on each unsigned fixture.
# ---------------------------------------------------------------------------


def test_python_permissive_unsigned_md_returns_missing_signature(verifier):
    path = FIXTURES_DIR / "unsigned.md"
    assert path.exists()
    result = verifier.verify_text(str(path))
    assert result.status == "missing_signature"
    assert result.signatures == []


def test_python_strict_unsigned_md_raises(verifier):
    path = FIXTURES_DIR / "unsigned.md"
    with pytest.raises(MissingSignatureError):
        verifier.verify_text(str(path), strict=True)


@pytest.mark.parametrize("name,fmt", [
    ("unsigned.png", "png"),
    ("unsigned.jpg", "jpeg"),
    ("unsigned.webp", "webp"),
])
def test_python_permissive_unsigned_image_returns_missing_signature(verifier, name, fmt):
    path = FIXTURES_DIR / name
    assert path.exists()
    result = verifier.verify_image(str(path))
    assert result.status == "missing_signature"


@pytest.mark.parametrize("name", ["unsigned.png", "unsigned.jpg", "unsigned.webp"])
def test_python_strict_unsigned_image_raises(verifier, name):
    path = FIXTURES_DIR / name
    assert path.exists()
    with pytest.raises(MissingSignatureError):
        verifier.verify_image(str(path), strict=True)


def test_python_strict_rust_signed_md_does_not_raise(verifier):
    """Sanity — strict mode only changes the missing-signature branch."""
    path = FIXTURES_DIR / "rust_signed_ed25519.md"
    result = verifier.verify_text(
        str(path), strict=True, key_dir=str(KEYS_DIR)
    )
    assert result.status == "signed"


# ---------------------------------------------------------------------------
# Acceptance #2 — Python signs locally, Rust CLI verifies (round trip).
# ---------------------------------------------------------------------------


def _resolve_jacs_cli() -> str | None:
    """Locate the `jacs` CLI binary. Prefer `cargo run` for predictable
    runtime in a checkout; fall back to `which jacs` if available."""
    # Prefer cargo run (works in a developer checkout and CI without a publish step).
    if shutil.which("cargo") is not None:
        return "cargo"
    if shutil.which("jacs") is not None:
        return "jacs"
    return None


def test_python_signs_rust_verifies(verifier, tmp_path):
    """Sign a file with Python, verify via the Rust CLI."""
    cli = _resolve_jacs_cli()
    if cli is None:
        pytest.skip("Neither cargo nor jacs CLI is available on PATH")

    target = tmp_path / "py_signed.md"
    original = "# Python-signed\n\nVerify me from Rust.\n"
    target.write_text(original)

    verifier.sign_text(str(target), no_backup=True)

    # Materialise the verifier's public key so the CLI can resolve it. The
    # ephemeral JacsClient exposes the raw native agent via the adapter
    # contract (the wrapper itself does not surface get_public_key_pem).
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    native = getattr(verifier._agent, "_native", verifier._agent)  # noqa: SLF001
    pem = native.get_public_key_pem()
    signer_id = verifier.agent_id
    encoded = signer_id.replace("..", "%2E%2E").replace(":", "%3A")
    (key_dir / f"{encoded}.public.pem").write_text(pem)

    # Build the CLI invocation. Use `cargo run -q --bin jacs` from the workspace
    # root for a hermetic test run.
    workspace_root = pathlib.Path(__file__).parent.parent.parent

    if cli == "cargo":
        cmd = [
            "cargo",
            "run",
            "-q",
            "--bin",
            "jacs",
            "--",
            "verify-text",
            str(target),
            "--key-dir",
            str(key_dir),
            "--json",
        ]
    else:
        cmd = [
            "jacs",
            "verify-text",
            str(target),
            "--key-dir",
            str(key_dir),
            "--json",
        ]

    completed = subprocess.run(
        cmd,
        cwd=str(workspace_root),
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "JACS_MAX_IAT_SKEW_SECONDS": "0"},
    )

    assert completed.returncode == 0, (
        f"jacs verify-text exited {completed.returncode}\n"
        f"stdout: {completed.stdout}\n"
        f"stderr: {completed.stderr}"
    )
    # `--json` prints pretty-printed JSON on stdout (multi-line).
    parsed = json.loads(completed.stdout)
    assert parsed.get("status") == "signed"
    sigs = parsed.get("signatures", [])
    assert len(sigs) == 1
    assert sigs[0].get("status") == "valid"
    assert sigs[0].get("signer_id") == verifier.agent_id
