"""Release-build contract for Python attestation support."""

from pathlib import Path
import tomllib

import jacs


def test_canonical_wheel_features_include_attestation():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    configuration = tomllib.loads(pyproject.read_text(encoding="utf-8"))

    assert "attestation" in configuration["tool"]["maturin"]["features"]


def test_installed_native_surface_includes_attestation_methods():
    for native_class in (jacs.JacsAgent, jacs.SimpleAgent):
        assert hasattr(native_class, "create_attestation")
        assert hasattr(native_class, "verify_attestation")
