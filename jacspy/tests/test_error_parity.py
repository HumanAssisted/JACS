"""
Error kind parity test for the Python binding.

Validates that all error kinds listed in the `error_kinds` array of
binding-core/tests/fixtures/parity_inputs.json are represented in the
Python binding's error type system.

The Rust ErrorKind enum has 13 variants. Python maps these through:
1. Custom exception classes in jacs.types (JacsError hierarchy)
2. Error message prefixes from the PyO3 native binding (RuntimeError)

This test ensures the Python codebase recognizes all error kinds.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "binding-core"
    / "tests"
    / "fixtures"
    / "parity_inputs.json"
)

# Mapping from Rust ErrorKind variant name to Python error representation.
# For each kind, we document:
# - python_class: The Python exception class that maps to this kind (if any)
# - message_pattern: A substring that appears in error messages for this kind
# - triggerable: Whether this error can be reliably triggered in tests
ERROR_KIND_MAP = {
    "LockFailed": {
        "python_class": None,  # Rare mutex poisoning; no dedicated Python class
        "message_pattern": "lock",
        "triggerable": False,  # Would require concurrent mutex poisoning
    },
    "AgentLoad": {
        "python_class": "ConfigError",
        "message_pattern": "Failed to load agent",
        "triggerable": True,
    },
    "Validation": {
        "python_class": None,  # Generic validation; uses RuntimeError
        "message_pattern": "Validation",
        "triggerable": True,
    },
    "SigningFailed": {
        "python_class": "SigningError",
        "message_pattern": "Sign",
        "triggerable": True,
    },
    "VerificationFailed": {
        "python_class": "VerificationError",
        "message_pattern": "Verification failed",
        "triggerable": True,
    },
    "DocumentFailed": {
        "python_class": None,  # Document ops; uses RuntimeError
        "message_pattern": "Document",
        "triggerable": False,  # Requires specific document state
    },
    "AgreementFailed": {
        "python_class": None,  # Agreement ops; uses RuntimeError
        "message_pattern": "Agreement",
        "triggerable": False,  # Requires agreement setup
    },
    "SerializationFailed": {
        "python_class": None,  # JSON/YAML serialization errors
        "message_pattern": "Serialization",
        "triggerable": True,
    },
    "InvalidArgument": {
        "python_class": None,  # Bad input; uses RuntimeError
        "message_pattern": "Invalid",
        "triggerable": True,
    },
    "TrustFailed": {
        "python_class": "TrustError",
        "message_pattern": "Trust",
        "triggerable": False,  # Requires trust store setup
    },
    "NetworkFailed": {
        "python_class": "NetworkError",
        "message_pattern": "Network",
        "triggerable": False,  # Requires network call
    },
    "KeyNotFound": {
        "python_class": "KeyNotFoundError",
        "message_pattern": "key",
        "triggerable": False,  # Requires missing key scenario
    },
    "Generic": {
        "python_class": "JacsError",
        "message_pattern": None,  # Catch-all; no specific pattern
        "triggerable": False,
    },
}


@pytest.fixture(scope="module")
def error_kinds_from_fixture() -> list:
    """Load error_kinds from the shared parity fixture."""
    assert FIXTURE_PATH.exists(), (
        f"Parity fixture not found at {FIXTURE_PATH}. "
        "Ensure binding-core/tests/fixtures/parity_inputs.json exists."
    )
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    kinds = data.get("error_kinds")
    assert kinds is not None, "parity_inputs.json should contain 'error_kinds' array"
    return kinds


def test_all_error_kinds_are_mapped(error_kinds_from_fixture: list):
    """Every error kind from the fixture must have an entry in ERROR_KIND_MAP."""
    unmapped = []
    for kind in error_kinds_from_fixture:
        if kind not in ERROR_KIND_MAP:
            unmapped.append(kind)

    assert not unmapped, (
        f"Error kinds from fixture not mapped in Python: {unmapped}. "
        "Add entries to ERROR_KIND_MAP in test_error_parity.py."
    )


def test_error_kind_map_has_no_stale_entries(error_kinds_from_fixture: list):
    """ERROR_KIND_MAP should not contain entries not in the fixture."""
    fixture_set = set(error_kinds_from_fixture)
    stale = [k for k in ERROR_KIND_MAP if k not in fixture_set]

    assert not stale, (
        f"ERROR_KIND_MAP contains stale entries not in fixture: {stale}. "
        "Remove them."
    )


def test_error_kinds_count(error_kinds_from_fixture: list):
    """There should be exactly 13 error kinds."""
    assert len(error_kinds_from_fixture) == 13, (
        f"Expected 13 error kinds, got {len(error_kinds_from_fixture)}."
    )
    assert len(ERROR_KIND_MAP) == 13, (
        f"ERROR_KIND_MAP has {len(ERROR_KIND_MAP)} entries, expected 13."
    )


def test_python_error_classes_exist():
    """All referenced Python error classes must be importable from jacs.types."""
    from jacs.types import (
        JacsError,
        ConfigError,
        AgentNotLoadedError,
        SigningError,
        VerificationError,
        TrustError,
        KeyNotFoundError,
        NetworkError,
    )

    # Verify the class hierarchy
    assert issubclass(ConfigError, JacsError)
    assert issubclass(AgentNotLoadedError, JacsError)
    assert issubclass(SigningError, JacsError)
    assert issubclass(VerificationError, JacsError)
    assert issubclass(TrustError, JacsError)
    assert issubclass(KeyNotFoundError, JacsError)
    assert issubclass(NetworkError, JacsError)


def test_python_error_classes_match_map():
    """Python classes referenced in ERROR_KIND_MAP must exist in jacs.types."""
    import jacs.types as types_mod

    for kind, info in ERROR_KIND_MAP.items():
        class_name = info.get("python_class")
        if class_name is None:
            continue
        assert hasattr(types_mod, class_name), (
            f"ERROR_KIND_MAP references '{class_name}' for {kind}, "
            f"but jacs.types has no such class."
        )
