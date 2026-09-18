"""PRD §4.2.6 / Issue 022 — Python parameterised drift test for MCP path
policy. Consumes the same JSON fixture as Rust + Node so the three
languages enforce identical policy.

Set ``JACS_MCP_BASE_DIR`` to a fresh tempdir per case, plus any per-case
env overrides (e.g., ``JACS_MCP_OVERWRITE_OK``). The Rust delegate
(``jacs_mcp_resolve_input_path``) is what we're exercising — Python is
just a thin shell.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest


def _fixture_path() -> Path:
    here = Path(__file__).resolve().parent
    # The fixture lives in the workspace under jacs-mcp/tests/fixtures/.
    repo_root = here.parent.parent
    return repo_root / "jacs-mcp" / "tests" / "fixtures" / "mcp_path_policy_cases.json"


@pytest.fixture(scope="module")
def fixture_cases():
    p = _fixture_path()
    if not p.is_file():
        pytest.skip(f"shared fixture not found at {p}")
    data = json.loads(p.read_text())
    assert data["schema_version"] == 1
    return data["cases"]


def _resolved_raw_path(case: dict) -> str:
    """Decode the case's raw_path (or raw_path_escaped for control chars)."""
    if "raw_path" in case:
        return case["raw_path"]
    esc = case["raw_path_escaped"]
    return bytes(esc, "utf-8").decode("unicode_escape")


def test_fixture_drives_python_path_policy(fixture_cases):
    from jacs.jacs import jacs_mcp_resolve_input_path  # delegate

    for case in fixture_cases:
        # Fresh tempdir per case as base.
        with tempfile.TemporaryDirectory() as base:
            # Materialise setup files / symlinks if required.
            setup = case.get("setup")
            if setup:
                if setup["kind"] == "file":
                    target = Path(base) / setup["name"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(setup.get("contents") or "")
                elif setup["kind"] == "symlink":
                    if os.name != "posix":
                        continue  # symlinks are unix-only in this matrix
                    outside = tempfile.mkdtemp()
                    try:
                        target = Path(outside) / "attacker_target" if setup.get(
                            "target_outside_base", True
                        ) else Path(base) / "inside_target"
                        target.write_bytes(b"sensitive")
                        link = Path(base) / setup["name"]
                        link.symlink_to(target)
                    except Exception as e:  # pragma: no cover
                        pytest.skip(f"symlink setup failed: {e}")

            # Build env: always set BASE_DIR; layer per-case env on top.
            env_overrides = {"JACS_MCP_BASE_DIR": base}
            for k, v in (case.get("env") or {}).items():
                env_overrides[k] = v
            # Default-clear env vars not in the case.
            env_overrides.setdefault("JACS_MCP_OVERWRITE_OK", "")
            env_overrides.setdefault("JACS_MCP_FOLLOW_SYMLINKS", "")

            saved = {k: os.environ.get(k) for k in env_overrides}
            try:
                for k, v in env_overrides.items():
                    if v == "":
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v

                raw = _resolved_raw_path(case)
                kind = case["kind"]
                expect = case["expect"]

                if expect == "accept":
                    # Should not raise.
                    jacs_mcp_resolve_input_path(raw, kind)
                elif expect == "reject":
                    with pytest.raises(ValueError) as exc_info:
                        jacs_mcp_resolve_input_path(raw, kind)
                    needle = case.get("reason_substring_lowercase")
                    if needle:
                        msg = str(exc_info.value).lower()
                        assert needle in msg, (
                            f"[case {case['id']}] error '{msg}' missing '{needle}'"
                        )
                else:  # pragma: no cover
                    raise AssertionError(f"unknown expect: {expect}")
            finally:
                for k, prev in saved.items():
                    if prev is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = prev
