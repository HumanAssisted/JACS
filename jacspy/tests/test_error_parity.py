"""
Error kind parity test for the Python binding.

Validates that all error kinds listed in the `error_kinds` array of
binding-core/tests/fixtures/parity_inputs.json are represented in the
Python binding's error type system.

The Rust ErrorKind enum has 13 variants. Python maps these through:
1. Custom exception classes in jacs.types (JacsError hierarchy)
2. Error message prefixes from the PyO3 native binding (RuntimeError)

This test ensures the Python codebase recognizes all error kinds.

KNOWN LIMITATION: Most error kinds (8 of 13) are validated structurally
only (mapping existence in ERROR_KIND_MAP), not behaviorally (actually
triggered at runtime). Only the 5 triggerable kinds are tested with
runtime assertions. The untriggerable kinds require specific states
(concurrent mutex poisoning, network calls, trust store setup, etc.)
that are impractical to set up in unit tests.
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
    "MissingSignature": {
        "python_class": "MissingSignatureError",
        "message_pattern": "no JACS signature found",
        # C1: strict-mode verify_text / verify_image raise this.
        # In permissive mode (default) it is still a typed return, not thrown.
        "triggerable": True,
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
    """There should be exactly 14 error kinds."""
    assert len(error_kinds_from_fixture) == 14, (
        f"Expected 14 error kinds, got {len(error_kinds_from_fixture)}."
    )
    assert len(ERROR_KIND_MAP) == 14, (
        f"ERROR_KIND_MAP has {len(ERROR_KIND_MAP)} entries, expected 14."
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
        MissingSignatureError,
    )

    # Verify the class hierarchy
    assert issubclass(ConfigError, JacsError)
    assert issubclass(AgentNotLoadedError, JacsError)
    assert issubclass(SigningError, JacsError)
    assert issubclass(VerificationError, JacsError)
    assert issubclass(MissingSignatureError, JacsError)
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


# =============================================================================
# Runtime trigger tests for triggerable error kinds
# =============================================================================

try:
    from jacs import SimpleAgent as _SA

    _NATIVE_AVAILABLE = True
except ImportError:
    _NATIVE_AVAILABLE = False


@pytest.mark.skipif(not _NATIVE_AVAILABLE, reason="native jacs module not built")
class TestTriggerableErrorKinds:
    """Actually trigger the error kinds marked as triggerable=True."""

    @pytest.fixture(autouse=True)
    def agent(self):
        self.agent, _agent_json = _SA.ephemeral("ed25519")

    def test_sign_message_handles_raw_strings(self):
        """Python sign_message wraps non-JSON raw strings -- should succeed, not throw.

        This is a KNOWN behavioral difference from Node/Go (see Issue 013):
        - Python sign_message takes any Python object, converts to serde_json::Value,
          then serializes. A Python string becomes a valid JSON string value.
        - Node signMessage takes a JSON string directly, so invalid JSON is rejected.
        - Both behaviors are correct for their respective API contracts.
        See parity_inputs.json 'sign_message_invalid_json_behavior' for documentation.
        """
        result = self.agent.sign_message("{{{bad json")
        assert isinstance(result, dict), "sign_message should return a dict"
        assert "raw" in result, "result should contain 'raw' key"
        # Verify the signed raw-string document round-trips
        self.agent.verify(result["raw"])

    def test_verification_failed_bad_document(self):
        """VerificationFailed: not a valid signed document."""
        with pytest.raises(Exception, match=r"(?i)verif|malform"):
            self.agent.verify("not a json document")

    def test_serialization_failed_on_verify(self):
        """SerializationFailed: verify with non-JSON input triggers parse error."""
        with pytest.raises(Exception, match=r"(?i)malform|json|parse|key must be"):
            self.agent.verify("not json at all {{{")

    def test_invalid_argument_bad_base64_key(self):
        """InvalidArgument: bad base64 key for verify_with_key."""
        signed = self.agent.sign_message('{"test": 1}')
        raw = signed["raw"]
        with pytest.raises(Exception, match=r"(?i)invalid.*base64|base64"):
            self.agent.verify_with_key(raw, "!!!notbase64!!!")
