"""Inline text sign/verify tests (PRD §3.1, §4.1, C1, C2). Task 10."""

from __future__ import annotations

import pytest

# Skip all tests if the native jacs module is not built
jacs = pytest.importorskip("jacs")

from jacs import MissingSignatureError
from jacs.testing import jacs_agent  # noqa: F401  # pytest fixture


# ---------------------------------------------------------------------------
# Content preservation (C2) and basic signing.
# ---------------------------------------------------------------------------


def test_sign_text_file_content_preserved_no_wrapper(tmp_path, jacs_agent):
    """C2: content bytes preserved; no -----BEGIN JACS SIGNED MESSAGE----- wrapper."""
    path = tmp_path / "README.md"
    original = "# Title\n\nHello world.\n"
    path.write_text(original)

    result = jacs_agent.sign_text(str(path))

    content = path.read_text()
    assert (
        "-----BEGIN JACS SIGNED MESSAGE-----" not in content
    ), "C2: plain content must not be wrapped"

    # Content prefix up to the first signature marker equals the original
    # (modulo one optional trailing LF).
    prefix_end = content.index("-----BEGIN JACS SIGNATURE-----")
    prefix = content[:prefix_end].rstrip("\n") + "\n"
    assert prefix == original

    # Signer id is populated from the ephemeral client.
    assert result.signer_id


def test_sign_text_block_body_is_yaml(tmp_path, jacs_agent):
    """C3: block body between markers is valid YAML with required fields."""
    yaml = pytest.importorskip("yaml")

    path = tmp_path / "x.md"
    path.write_text("hi\n")
    jacs_agent.sign_text(str(path))

    content = path.read_text()
    start = content.index("-----BEGIN JACS SIGNATURE-----\n") + len(
        "-----BEGIN JACS SIGNATURE-----\n"
    )
    end = content.index("\n-----END JACS SIGNATURE-----")
    body = content[start:end]
    parsed = yaml.safe_load(body)

    assert "signer" in parsed
    assert "algorithm" in parsed
    assert "signedContentHash" in parsed
    assert "signature" in parsed


# ---------------------------------------------------------------------------
# Permissive (default) vs strict (C1) — missing-signature case.
# ---------------------------------------------------------------------------


def test_verify_text_permissive_missing_signature_returns_status_not_raises(
    tmp_path, jacs_agent
):
    """C1 permissive: missing-signature returns typed status, no exception."""
    path = tmp_path / "plain.md"
    path.write_text("plain content\n")

    result = jacs_agent.verify_text(str(path))

    assert result.status == "missing_signature"
    assert result.signatures == []


def test_verify_text_strict_missing_signature_raises(tmp_path, jacs_agent):
    """C1 strict: missing-signature raises MissingSignatureError."""
    path = tmp_path / "plain.md"
    path.write_text("plain content\n")

    with pytest.raises(MissingSignatureError, match="no JACS signature found"):
        jacs_agent.verify_text(str(path), strict=True)


def test_verify_text_valid_after_sign(tmp_path, jacs_agent):
    """Default-mode verify after sign reports status 'signed' and signature entry."""
    path = tmp_path / "ok.md"
    path.write_text("content\n")
    jacs_agent.sign_text(str(path))

    result = jacs_agent.verify_text(str(path))

    assert result.status == "signed"
    assert len(result.signatures) == 1
    assert result.signatures[0].status == "valid"


def test_verify_text_strict_valid_does_not_raise(tmp_path, jacs_agent):
    """C1: strict only changes the missing-signature branch — valid still passes."""
    path = tmp_path / "ok2.md"
    path.write_text("x\n")
    jacs_agent.sign_text(str(path))

    result = jacs_agent.verify_text(str(path), strict=True)
    assert result.status == "signed"


# ---------------------------------------------------------------------------
# Algorithm coverage: pq2025 sign + verify round trip.
# ---------------------------------------------------------------------------


def test_sign_verify_text_pq2025(tmp_path):
    """JacsClient.ephemeral accepts an algorithm arg — round trip through the binding."""
    from jacs import JacsClient

    with JacsClient.ephemeral(algorithm="pq2025") as client:
        path = tmp_path / "pq.md"
        path.write_text("hello\n")
        client.sign_text(str(path))

        result = client.verify_text(str(path))
        assert result.status == "signed"
        assert result.signatures[0].algorithm == "pq2025"


# ---------------------------------------------------------------------------
# Duplicate-signer behaviour.
# ---------------------------------------------------------------------------


def test_sign_text_duplicate_signer_noop(tmp_path, jacs_agent):
    """Signing the same file twice by the same agent is an idempotent no-op."""
    path = tmp_path / "dup.md"
    path.write_text("same\n")
    jacs_agent.sign_text(str(path))
    first = path.read_bytes()

    jacs_agent.sign_text(str(path))
    second = path.read_bytes()

    assert first == second
    assert second.count(b"-----BEGIN JACS SIGNATURE-----") == 1


# ---------------------------------------------------------------------------
# Multi-signer: C2 content preservation across distinct agents.
# ---------------------------------------------------------------------------


def test_sign_text_multi_signer_content_preserved(tmp_path):
    """Two distinct JacsClient instances append two blocks; prefix is unchanged."""
    from jacs import JacsClient

    with JacsClient.ephemeral() as a, JacsClient.ephemeral() as b:
        path = tmp_path / "multi.md"
        original = "# Title\n\npara\n"
        path.write_text(original)

        a.sign_text(str(path))
        b.sign_text(str(path))

        content = path.read_text()
        assert content.count("-----BEGIN JACS SIGNATURE-----") == 2

        prefix_end = content.index("-----BEGIN JACS SIGNATURE-----")
        assert content[:prefix_end].rstrip("\n") + "\n" == original
