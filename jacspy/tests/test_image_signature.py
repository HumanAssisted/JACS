"""Image sign/verify/extract tests (PRD §3.2, §4.2, C1). Task 10.

Each test uses an in-memory PIL image to avoid committing binary fixtures.
``pillow`` is listed in ``pyproject.toml`` dev extras.
"""

from __future__ import annotations

import pytest

# Skip entire module if native jacs module is not built.
jacs = pytest.importorskip("jacs")

# Skip if PIL isn't available — tests are dev-only.
PIL = pytest.importorskip("PIL")
from PIL import Image  # noqa: E402

from jacs import MissingSignatureError  # noqa: E402
from jacs.testing import jacs_agent  # noqa: F401, E402  # pytest fixture


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _write_unsigned_png(path):
    Image.new("RGBA", (16, 16), (255, 0, 0, 255)).save(str(path), format="PNG")


def _write_unsigned_jpeg(path):
    Image.new("RGB", (16, 16), (0, 0, 255)).save(str(path), format="JPEG")


def _write_unsigned_webp(path):
    Image.new("RGB", (16, 16), (0, 255, 0)).save(str(path), format="WEBP")


# ---------------------------------------------------------------------------
# sign_image -> verify_image round-trips per format.
# ---------------------------------------------------------------------------


def test_sign_image_png(tmp_path, jacs_agent):
    src = tmp_path / "in.png"
    out = tmp_path / "out.png"
    _write_unsigned_png(src)

    result = jacs_agent.sign_image(str(src), str(out))

    assert result.format == "png"
    verify = jacs_agent.verify_image(str(out))
    assert verify.status == "valid"


def test_sign_image_jpeg(tmp_path, jacs_agent):
    src = tmp_path / "in.jpg"
    out = tmp_path / "out.jpg"
    _write_unsigned_jpeg(src)

    result = jacs_agent.sign_image(str(src), str(out))

    assert result.format == "jpeg"
    verify = jacs_agent.verify_image(str(out))
    assert verify.status == "valid"


def test_sign_image_webp(tmp_path, jacs_agent):
    src = tmp_path / "in.webp"
    out = tmp_path / "out.webp"
    _write_unsigned_webp(src)

    result = jacs_agent.sign_image(str(src), str(out))

    assert result.format == "webp"
    verify = jacs_agent.verify_image(str(out))
    assert verify.status == "valid"


# ---------------------------------------------------------------------------
# Permissive vs strict (C1).
# ---------------------------------------------------------------------------


def test_verify_image_permissive_missing_signature_status(tmp_path, jacs_agent):
    src = tmp_path / "plain.png"
    _write_unsigned_png(src)

    r = jacs_agent.verify_image(str(src))
    assert r.status == "missing_signature"


def test_verify_image_strict_missing_signature_raises(tmp_path, jacs_agent):
    src = tmp_path / "plain.png"
    _write_unsigned_png(src)

    with pytest.raises(MissingSignatureError):
        jacs_agent.verify_image(str(src), strict=True)


# ---------------------------------------------------------------------------
# extract_media_signature.
# ---------------------------------------------------------------------------


def test_extract_media_signature_png(tmp_path, jacs_agent):
    src = tmp_path / "in.png"
    out = tmp_path / "out.png"
    _write_unsigned_png(src)
    jacs_agent.sign_image(str(src), str(out))

    payload = jacs_agent.extract_media_signature(str(out))
    assert payload is not None
    assert isinstance(payload, str)
    assert len(payload) > 0


def test_extract_media_signature_unsigned_returns_none(tmp_path, jacs_agent):
    """Unsigned images (all three formats) return None from extract_media_signature."""
    for name, writer in (
        ("plain.png", _write_unsigned_png),
        ("plain.jpg", _write_unsigned_jpeg),
        ("plain.webp", _write_unsigned_webp),
    ):
        path = tmp_path / name
        writer(path)
        payload = jacs_agent.extract_media_signature(str(path))
        assert payload is None, f"{name} returned {payload!r}"


def test_extract_media_signature_raw_payload_flag(tmp_path, jacs_agent):
    """raw_payload=True returns a base64url-style string (no JSON braces)."""
    src = tmp_path / "in.png"
    out = tmp_path / "out.png"
    _write_unsigned_png(src)
    jacs_agent.sign_image(str(src), str(out))

    decoded = jacs_agent.extract_media_signature(str(out))
    raw = jacs_agent.extract_media_signature(str(out), raw_payload=True)

    assert decoded is not None and raw is not None
    assert decoded != raw, "raw_payload should differ from decoded JSON"
    # Decoded JSON starts with '{'; raw base64url should not.
    assert not raw.lstrip().startswith("{"), "raw_payload should be base64url"
