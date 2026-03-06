"""Tests for deprecation warnings on alias methods.

Verifies that deprecated wrap_* methods emit DeprecationWarning when the
``JACS_SHOW_DEPRECATIONS`` environment variable is set, and remain silent
when it is not set.
"""

import json
import os
import warnings
from unittest.mock import MagicMock

import pytest

from jacs.a2a import JACSA2AIntegration, _deprecation_warn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_client() -> MagicMock:
    """Return a mock JacsClient with a stubbed _agent.sign_request."""
    client = MagicMock()
    client._agent.sign_request.return_value = json.dumps({
        "jacsId": "dep-test-1",
        "jacsVersion": "v1",
        "jacsType": "a2a-task",
        "jacsLevel": "artifact",
        "a2aArtifact": {"data": "test"},
    })
    return client


# ---------------------------------------------------------------------------
# _deprecation_warn helper
# ---------------------------------------------------------------------------

class TestDeprecationWarnHelper:
    def test_emits_warning_when_env_set(self, monkeypatch):
        monkeypatch.setenv("JACS_SHOW_DEPRECATIONS", "1")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _deprecation_warn("old_method", "new_method")
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "old_method() is deprecated" in str(w[0].message)
        assert "new_method()" in str(w[0].message)

    def test_silent_when_env_not_set(self, monkeypatch):
        monkeypatch.delenv("JACS_SHOW_DEPRECATIONS", raising=False)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _deprecation_warn("old_method", "new_method")
        assert len(w) == 0

    def test_silent_when_env_empty(self, monkeypatch):
        monkeypatch.setenv("JACS_SHOW_DEPRECATIONS", "")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _deprecation_warn("old_method", "new_method")
        assert len(w) == 0


# ---------------------------------------------------------------------------
# wrap_artifact_with_provenance deprecation
# ---------------------------------------------------------------------------

def _jacs_deprecation_warnings(warning_list):
    """Filter a list of captured warnings to only JACS deprecation warnings."""
    return [
        w for w in warning_list
        if issubclass(w.category, DeprecationWarning)
        and "is deprecated, use" in str(w.message)
    ]


class TestWrapArtifactDeprecation:
    def test_emits_deprecation_warning(self, monkeypatch):
        """wrap_artifact_with_provenance emits DeprecationWarning when env is set."""
        monkeypatch.setenv("JACS_SHOW_DEPRECATIONS", "1")
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            a2a.wrap_artifact_with_provenance({"data": "test"}, "task")

        jacs_warnings = _jacs_deprecation_warnings(w)
        assert len(jacs_warnings) == 1
        assert "wrap_artifact_with_provenance" in str(jacs_warnings[0].message)
        assert "sign_artifact" in str(jacs_warnings[0].message)

    def test_silent_without_env(self, monkeypatch):
        """wrap_artifact_with_provenance emits NO JACS warning when env is not set."""
        monkeypatch.delenv("JACS_SHOW_DEPRECATIONS", raising=False)
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            a2a.wrap_artifact_with_provenance({"data": "test"}, "task")

        jacs_warnings = _jacs_deprecation_warnings(w)
        assert len(jacs_warnings) == 0

    def test_still_works(self):
        """Deprecated method returns the same result as the canonical method."""
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)

        result = a2a.wrap_artifact_with_provenance({"data": "test"}, "task")
        assert result["jacsId"] == "dep-test-1"
        assert result["a2aArtifact"] == {"data": "test"}
        client._agent.sign_request.assert_called_once()

    def test_with_parent_signatures(self, monkeypatch):
        """Deprecated method passes parent_signatures through correctly."""
        monkeypatch.setenv("JACS_SHOW_DEPRECATIONS", "1")
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)
        parents = [{"sig": "abc"}]

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = a2a.wrap_artifact_with_provenance(
                {"data": "test"}, "task", parent_signatures=parents
            )

        # JACS deprecation warning was emitted
        jacs_warnings = _jacs_deprecation_warnings(w)
        assert len(jacs_warnings) == 1
        assert issubclass(jacs_warnings[0].category, DeprecationWarning)
        # Functionality preserved
        assert result["jacsId"] == "dep-test-1"
        call_args = client._agent.sign_request.call_args[0][0]
        assert "jacsParentSignatures" in call_args


# ---------------------------------------------------------------------------
# sign_artifact (canonical) does NOT warn
# ---------------------------------------------------------------------------

class TestSignArtifactNoWarning:
    def test_no_warning_even_when_env_set(self, monkeypatch):
        """sign_artifact() never emits JACS deprecation warnings."""
        monkeypatch.setenv("JACS_SHOW_DEPRECATIONS", "1")
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            a2a.sign_artifact({"data": "test"}, "task")

        jacs_warnings = _jacs_deprecation_warnings(w)
        assert len(jacs_warnings) == 0
