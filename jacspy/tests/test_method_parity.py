"""
Method enumeration parity test for the Python binding.

Validates that all methods listed in
binding-core/tests/fixtures/method_parity.json are exposed in the Python
binding (via SimpleAgent PyO3 class), with documented exclusions and
name mappings.

This is a *structural* test (method names), not a *behavioral* test.
It complements, not duplicates, test_parity.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Skip all tests if the native jacs module is not built
jacs = pytest.importorskip("jacs")

from jacs import SimpleAgent

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "binding-core"
    / "tests"
    / "fixtures"
    / "method_parity.json"
)

# Methods that are intentionally Rust-only and not exposed in Python.
# Each exclusion has a comment explaining why.
EXCLUDED_FROM_PYTHON = {
    # inner_ref returns a raw Rust reference; not meaningful across FFI
    "inner_ref",
    # from_agent wraps a Rust SimpleAgent; not callable from Python
    "from_agent",
    # load_with_info is an internal Rust helper; Python uses load() directly
    "load_with_info",
}

# Rust method name -> Python attribute name mapping.
# When the Python binding uses a different name than Rust, document it here.
PYTHON_NAME_MAP = {
    "create": "create",
    "load": "load",
    "ephemeral": "ephemeral",
    "create_with_params": "create_with_params",
    "get_agent_id": "get_agent_id",
    "key_id": "key_id",
    "is_strict": "is_strict",
    "config_path": "config_path",
    "export_agent": "export_agent",
    "get_public_key_pem": "get_public_key_pem",
    "get_public_key_base64": "get_public_key_base64",
    "diagnostics": "diagnostics",
    "verify_self": "verify_self",
    "verify_json": "verify",
    "verify_with_key_json": "verify_with_key",
    "verify_by_id_json": "verify_by_id",
    "sign_message_json": "sign_message",
    "sign_raw_bytes_base64": "sign_string",
    "sign_file_json": "sign_file",
    "to_yaml": "to_yaml",
    "from_yaml": "from_yaml",
    "to_html": "to_html",
    "from_html": "from_html",
    "rotate_keys": "rotate_keys",
}


@pytest.fixture(scope="module")
def method_parity() -> dict:
    """Load the shared method parity fixture file."""
    assert FIXTURE_PATH.exists(), (
        f"Method parity fixture not found at {FIXTURE_PATH}. "
        "Ensure binding-core/tests/fixtures/method_parity.json exists."
    )
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def test_python_method_parity_against_fixture(method_parity: dict):
    """All non-excluded methods from the fixture must exist on SimpleAgent."""
    all_methods = method_parity["all_methods_flat"]

    missing = []
    for rust_name in all_methods:
        if rust_name in EXCLUDED_FROM_PYTHON:
            continue

        python_name = PYTHON_NAME_MAP.get(rust_name, rust_name)
        if not hasattr(SimpleAgent, python_name):
            missing.append(f"{rust_name} (expected as '{python_name}')")

    assert not missing, (
        f"Python SimpleAgent is missing {len(missing)} methods from method_parity.json:\n"
        + "\n".join(f"  - {m}" for m in missing)
        + "\n\nIf a method was intentionally excluded, add it to EXCLUDED_FROM_PYTHON. "
        + "If it has a different name in Python, add it to PYTHON_NAME_MAP."
    )


def test_python_exclusions_are_valid(method_parity: dict):
    """Every excluded method must actually exist in the fixture."""
    all_methods = set(method_parity["all_methods_flat"])

    invalid_exclusions = EXCLUDED_FROM_PYTHON - all_methods
    assert not invalid_exclusions, (
        f"EXCLUDED_FROM_PYTHON contains methods not in the fixture: {invalid_exclusions}. "
        "Remove stale exclusions."
    )


def test_python_name_map_covers_all_non_excluded(method_parity: dict):
    """Every non-excluded method should have a mapping (even if identity)."""
    all_methods = method_parity["all_methods_flat"]

    unmapped = []
    for rust_name in all_methods:
        if rust_name in EXCLUDED_FROM_PYTHON:
            continue
        if rust_name not in PYTHON_NAME_MAP:
            unmapped.append(rust_name)

    assert not unmapped, (
        f"Methods without PYTHON_NAME_MAP entry: {unmapped}. "
        "Add a mapping (even rust_name -> rust_name if the name is the same)."
    )


def test_python_name_map_has_no_stale_entries(method_parity: dict):
    """PYTHON_NAME_MAP should not contain methods that don't exist in the fixture."""
    all_methods = set(method_parity["all_methods_flat"])

    stale = set(PYTHON_NAME_MAP.keys()) - all_methods
    assert not stale, (
        f"PYTHON_NAME_MAP contains methods not in the fixture: {stale}. "
        "Remove stale mappings."
    )


def test_python_exclusions_are_still_needed():
    """Check if excluded methods now exist on SimpleAgent.

    If an excluded method becomes available at runtime (e.g., after
    rebuilding the native module), this test fails to prompt removal
    of the exclusion. This turns the TODO in EXCLUDED_FROM_PYTHON
    into an automated check.
    """
    newly_available = []
    for method_name in EXCLUDED_FROM_PYTHON:
        # Skip internal-only exclusions that will never appear on the class
        if method_name in ("inner_ref", "from_agent", "load_with_info"):
            continue
        # Check if the method is now available on SimpleAgent
        python_name = PYTHON_NAME_MAP.get(method_name, method_name)
        if hasattr(SimpleAgent, python_name):
            newly_available.append(
                f"{method_name} (as '{python_name}') is now available on SimpleAgent"
            )

    assert not newly_available, (
        "The following excluded methods are now available on SimpleAgent. "
        "Remove them from EXCLUDED_FROM_PYTHON and add them to PYTHON_NAME_MAP:\n"
        + "\n".join(f"  - {m}" for m in newly_available)
    )
