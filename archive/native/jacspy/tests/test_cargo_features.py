from pathlib import Path
import re


def test_pyo3_auto_initialize_is_not_unconditional():
    """Keep auto-initialize optional so extension-module builds work in CI."""
    cargo_toml = (Path(__file__).resolve().parents[1] / "Cargo.toml").read_text()

    pyo3_dep = re.search(r"^pyo3\s*=\s*\{[^}]*\}", cargo_toml, flags=re.MULTILINE)
    assert pyo3_dep, "Expected a pyo3 dependency entry in jacspy/Cargo.toml"
    assert "auto-initialize" not in pyo3_dep.group(0), (
        "pyo3 dependency must not unconditionally enable auto-initialize; "
        "it breaks extension-module builds on static-only Python environments."
    )

    assert 'auto-initialize = ["pyo3/auto-initialize"]' in cargo_toml, (
        "Expected an explicit optional auto-initialize feature mapping."
    )
    assert 'extension-module = ["pyo3/extension-module"]' in cargo_toml, (
        "Expected extension-module feature mapping to remain available."
    )
