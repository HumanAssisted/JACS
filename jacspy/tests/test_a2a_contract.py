"""
Contract tests for Python A2A verification output against the shared schema.

These tests validate that JACSA2AIntegration.verify_wrapped_artifact() output
conforms to the canonical a2a-verification-result.schema.json defined in Task 001
of the ATTESTATION_A2A_RESOLUTION PRD (Phase 0).

EXPECTED STATE: These tests are designed to FAIL in the Red phase.  The Python
wrapper currently returns snake_case field names (e.g. ``signer_id``) and lacks
the ``status`` enum field.  They will pass after Tasks 007/008/011 align the
wrapper output to the shared contract.

Fixture files in ``fixtures/a2a_contract/`` are copies of the canonical fixtures
from ``jacs/tests/fixtures/a2a_contract/``.  The schema is loaded from
``jacs/schemas/a2a-verification-result.schema.json``.
"""

import json
import pathlib
from typing import Any, Dict

import pytest
from unittest.mock import MagicMock

import jsonschema

from jacs.a2a import JACSA2AIntegration


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_TESTS_DIR = pathlib.Path(__file__).parent.absolute()
_FIXTURES_DIR = _TESTS_DIR / "fixtures" / "a2a_contract"
_SCHEMA_PATH = _TESTS_DIR.parent.parent / "jacs" / "schemas" / "a2a-verification-result.schema.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_fixture(name: str) -> Dict[str, Any]:
    """Load a contract fixture JSON file by name (without extension)."""
    path = _FIXTURES_DIR / f"{name}.json"
    with open(path) as f:
        return json.load(f)


def _load_schema() -> Dict[str, Any]:
    """Load the canonical verification-result JSON schema."""
    with open(_SCHEMA_PATH) as f:
        return json.load(f)


def _make_mock_client() -> MagicMock:
    """Return a mock JacsClient with a mock _agent."""
    client = MagicMock()
    client._agent = MagicMock()
    return client


def _make_integration(*, verify_succeeds: bool = True) -> JACSA2AIntegration:
    """Create a JACSA2AIntegration with a mock client.

    Args:
        verify_succeeds: If True, the mock verify_response returns
            successfully.  If False, it raises RuntimeError to simulate
            a failed verification.
    """
    client = _make_mock_client()
    if verify_succeeds:
        client._agent.verify_response.return_value = {"data": "mock"}
    else:
        client._agent.verify_response.side_effect = RuntimeError("signature mismatch")
    return JACSA2AIntegration(client)


def _make_wrapped_artifact(
    *,
    signer_id: str = "agent-test-001",
    signer_version: str = "v1",
    artifact_type: str = "a2a-task",
    timestamp: str = "2025-06-01T00:00:00Z",
    artifact: dict | None = None,
    parent_signatures: list | None = None,
) -> Dict[str, Any]:
    """Build a minimal wrapped artifact dict for passing to verify_wrapped_artifact."""
    doc: Dict[str, Any] = {
        "jacsId": f"artifact-{signer_id}",
        "jacsType": artifact_type,
        "jacsVersionDate": timestamp,
        "a2aArtifact": artifact or {"name": "test-artifact"},
        "jacsSignature": {
            "agentID": signer_id,
            "agentVersion": signer_version,
            "publicKeyHash": "abc123",
        },
    }
    if parent_signatures is not None:
        doc["jacsParentSignatures"] = parent_signatures
    return doc


# ---------------------------------------------------------------------------
# Markers
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.contract


# ---------------------------------------------------------------------------
# Unit tests: output shape conformance
# ---------------------------------------------------------------------------


class TestVerifyResultShape:
    """Unit tests verifying that verify_wrapped_artifact() output contains
    the fields required by the shared contract schema.

    These tests are expected to fail until TASK_007 aligns the Python wrapper
    output to use the canonical field names and status enum.
    """

    def test_verify_result_has_status_field(self):
        """Output must contain a ``status`` field (string or object).

        The current Python wrapper only returns ``valid`` (boolean) without a
        ``status`` enum.  This test is expected to fail until TASK_007 adds
        the ``status`` field to the output.

        Schema ref: /properties/status -> VerificationStatus
        """
        integration = _make_integration(verify_succeeds=True)
        wrapped = _make_wrapped_artifact()

        result = integration.verify_wrapped_artifact(wrapped)

        assert "status" in result, (
            "verify_wrapped_artifact() output must contain a 'status' field. "
            "Current output keys: " + ", ".join(sorted(result.keys()))
        )
        # status must be either a string or a dict (for Unverified/Invalid variants)
        assert isinstance(result["status"], (str, dict)), (
            f"'status' must be a string or dict, got {type(result['status']).__name__}"
        )

    def test_verify_result_status_values_verified(self):
        """When verification succeeds, ``status`` must be one of ``Verified``
        or ``SelfSigned``.

        This test is expected to fail until TASK_007 adds the ``status`` field.

        Schema ref: /definitions/VerificationStatus
        """
        integration = _make_integration(verify_succeeds=True)
        wrapped = _make_wrapped_artifact()

        result = integration.verify_wrapped_artifact(wrapped)

        status = result.get("status")
        valid_statuses = {"Verified", "SelfSigned"}
        assert status in valid_statuses, (
            f"For a valid artifact, status must be one of {valid_statuses}, "
            f"got {status!r}"
        )

    def test_verify_result_status_values_invalid(self):
        """When verification fails, ``status`` must be an object with either
        ``Unverified`` or ``Invalid`` key.

        This test is expected to fail until TASK_007 adds the ``status`` field.

        Schema ref: /definitions/VerificationStatus (Unverified / Invalid variants)
        """
        integration = _make_integration(verify_succeeds=False)
        wrapped = _make_wrapped_artifact()

        result = integration.verify_wrapped_artifact(wrapped)

        status = result.get("status")
        if isinstance(status, str):
            # Should NOT be a simple string for failed verification
            pytest.fail(
                f"For a failed verification, status should be an object "
                f"(Unverified/Invalid), not a plain string: {status!r}"
            )
        elif isinstance(status, dict):
            valid_keys = {"Unverified", "Invalid"}
            actual_keys = set(status.keys())
            assert actual_keys & valid_keys, (
                f"Failed verification status dict must contain one of "
                f"{valid_keys}, got keys: {actual_keys}"
            )
            # The inner value must have a 'reason' string
            for key in valid_keys & actual_keys:
                assert isinstance(status[key], dict), (
                    f"status['{key}'] must be a dict with a 'reason' field"
                )
                assert "reason" in status[key], (
                    f"status['{key}'] must contain a 'reason' field"
                )
                assert isinstance(status[key]["reason"], str), (
                    f"status['{key}']['reason'] must be a string"
                )
        else:
            pytest.fail(
                f"'status' must be a string or dict, got {type(status).__name__}: {status!r}"
            )

    def test_verify_result_has_trust_block(self):
        """When ``assess_trust=True``, the output must contain ``trustAssessment``
        and ``trustLevel`` fields matching the schema structure.

        This test is expected to fail until TASK_008 aligns the trust output.
        The current wrapper returns a ``trust`` dict with snake_case keys instead.

        Schema ref: /properties/trustAssessment, /properties/trustLevel
        """
        integration = _make_integration(verify_succeeds=True)
        wrapped = _make_wrapped_artifact(artifact_type="a2a-task")

        # assess_trust=True triggers the trust assessment path
        result = integration.verify_wrapped_artifact(wrapped, assess_trust=True)

        assert "trustAssessment" in result, (
            "Output must contain 'trustAssessment' (camelCase) when "
            "assess_trust=True. Current output keys: " + ", ".join(sorted(result.keys()))
        )
        assert "trustLevel" in result, (
            "Output must contain 'trustLevel' (camelCase) when "
            "assess_trust=True. Current output keys: " + ", ".join(sorted(result.keys()))
        )

    def test_verify_result_trust_policy_values(self):
        """``trustAssessment.allowed`` must be boolean and ``trustAssessment.policy``
        must be one of the defined policy enum values.

        This test is expected to fail until TASK_008 aligns the trust output.

        Schema ref: /definitions/TrustAssessment, /definitions/A2ATrustPolicy
        """
        integration = _make_integration(verify_succeeds=True)
        wrapped = _make_wrapped_artifact(artifact_type="a2a-task")

        result = integration.verify_wrapped_artifact(wrapped, assess_trust=True)

        trust = result.get("trustAssessment")
        if trust is None:
            pytest.fail(
                "Missing 'trustAssessment' in output. "
                "Current output keys: " + ", ".join(sorted(result.keys()))
            )

        assert isinstance(trust.get("allowed"), bool), (
            f"trustAssessment.allowed must be boolean, got "
            f"{type(trust.get('allowed')).__name__}"
        )

        valid_policies = {"Open", "Verified", "Strict"}
        policy = trust.get("policy")
        assert policy in valid_policies, (
            f"trustAssessment.policy must be one of {valid_policies}, got {policy!r}"
        )

    def test_verify_result_preserves_valid_field(self):
        """The ``valid`` boolean field must still be present for backward
        compatibility, alongside the new ``status`` field.

        This test SHOULD pass even before alignment, since ``valid`` is
        already present in the current output.

        Schema ref: /properties/valid
        """
        integration = _make_integration(verify_succeeds=True)
        wrapped = _make_wrapped_artifact()

        result = integration.verify_wrapped_artifact(wrapped)

        assert "valid" in result, (
            "Output must contain 'valid' boolean field for backward compat"
        )
        assert isinstance(result["valid"], bool), (
            f"'valid' must be boolean, got {type(result['valid']).__name__}"
        )
        assert result["valid"] is True, (
            "For a successfully verified artifact, 'valid' must be True"
        )

    def test_verify_result_uses_camel_case_fields(self):
        """All field names in the output must use camelCase as specified
        by the shared schema.

        This test is expected to fail until TASK_007 converts field names.
        The current wrapper returns snake_case names like ``signer_id``,
        ``signer_version``, ``artifact_type``, ``original_artifact``.

        Schema ref: all top-level properties
        """
        integration = _make_integration(verify_succeeds=True)
        wrapped = _make_wrapped_artifact()

        result = integration.verify_wrapped_artifact(wrapped)

        # These are the camelCase field names required by the schema
        required_camel_case_fields = {
            "signerId",
            "signerVersion",
            "artifactType",
            "timestamp",
            "originalArtifact",
            "parentSignaturesValid",
            "parentVerificationResults",
        }

        # These are the snake_case equivalents the current code produces
        snake_case_fields = {
            "signer_id",
            "signer_version",
            "artifact_type",
            "original_artifact",
            "parent_signatures_count",
            "parent_verification_results",
            "parent_signatures_valid",
        }

        found_snake_case = snake_case_fields & set(result.keys())
        missing_camel_case = required_camel_case_fields - set(result.keys())

        if found_snake_case:
            pytest.fail(
                f"Output uses snake_case field names {found_snake_case} "
                f"instead of camelCase. Missing camelCase fields: {missing_camel_case}"
            )

        assert not missing_camel_case, (
            f"Missing required camelCase fields: {missing_camel_case}"
        )


# ---------------------------------------------------------------------------
# Integration tests: fixture conformance
# ---------------------------------------------------------------------------


class TestContractFixtures:
    """Integration tests that compare Python wrapper output against the
    canonical fixture files field-by-field.

    Each test loads a fixture from ``fixtures/a2a_contract/``, runs the
    wrapper, and asserts that the output matches the expected field names
    and structure defined in the fixture.

    These tests are expected to fail until Tasks 007/008/011 align the
    Python wrapper output to the canonical schema.
    """

    @pytest.fixture(scope="class")
    def schema(self) -> Dict[str, Any]:
        """Load the canonical JSON schema once per class."""
        return _load_schema()

    def test_contract_self_signed(self, schema: Dict[str, Any]):
        """Verify Python output for a self-signed artifact matches the
        ``self_signed_verified.json`` fixture structure.

        Expected: status="SelfSigned", valid=true, no trust fields.
        This test is expected to fail until TASK_007 adds the status field
        and converts to camelCase field names.

        Fixture: fixtures/a2a_contract/self_signed_verified.json
        """
        expected = _load_fixture("self_signed_verified")

        # Simulate self-signed verification (succeeds)
        integration = _make_integration(verify_succeeds=True)
        wrapped = _make_wrapped_artifact(
            signer_id=expected["signerId"],
            signer_version=expected["signerVersion"],
            artifact_type=expected["artifactType"],
            timestamp=expected["timestamp"],
            artifact=expected["originalArtifact"],
        )

        result = integration.verify_wrapped_artifact(wrapped)

        # Validate against the JSON schema first
        try:
            jsonschema.validate(instance=result, schema=schema)
        except jsonschema.ValidationError as exc:
            pytest.fail(
                f"Output does not conform to a2a-verification-result schema: "
                f"{exc.message}\n\nActual output keys: {sorted(result.keys())}\n"
                f"Expected required keys: {schema.get('required', [])}"
            )

        # Field-by-field comparison against fixture
        assert result.get("status") == expected["status"], (
            f"status: expected {expected['status']!r}, got {result.get('status')!r}"
        )
        assert result.get("valid") == expected["valid"], (
            f"valid: expected {expected['valid']!r}, got {result.get('valid')!r}"
        )
        assert result.get("signerId") == expected["signerId"], (
            f"signerId: expected {expected['signerId']!r}, got {result.get('signerId')!r}"
        )
        assert result.get("signerVersion") == expected["signerVersion"], (
            f"signerVersion: expected {expected['signerVersion']!r}, "
            f"got {result.get('signerVersion')!r}"
        )
        assert result.get("artifactType") == expected["artifactType"], (
            f"artifactType: expected {expected['artifactType']!r}, "
            f"got {result.get('artifactType')!r}"
        )
        assert result.get("parentSignaturesValid") == expected["parentSignaturesValid"]
        assert result.get("parentVerificationResults") == expected["parentVerificationResults"]
        assert result.get("originalArtifact") == expected["originalArtifact"]

    def test_contract_foreign_verified(self, schema: Dict[str, Any]):
        """Verify Python output for a foreign-verified artifact matches the
        ``foreign_verified.json`` fixture structure.

        Expected: status="Verified", valid=true, trustAssessment present.
        This test is expected to fail until TASK_007/008 add status and
        trustAssessment fields.

        Fixture: fixtures/a2a_contract/foreign_verified.json
        """
        expected = _load_fixture("foreign_verified")

        integration = _make_integration(verify_succeeds=True)
        wrapped = _make_wrapped_artifact(
            signer_id=expected["signerId"],
            signer_version=expected["signerVersion"],
            artifact_type=expected["artifactType"],
            timestamp=expected["timestamp"],
            artifact=expected["originalArtifact"],
            parent_signatures=[
                {
                    "jacsId": "parent-artifact-001",
                    "jacsSignature": {
                        "agentID": "agent-self-001",
                        "agentVersion": "v1-self",
                    },
                    "a2aArtifact": {},
                }
            ],
        )

        result = integration.verify_wrapped_artifact(wrapped)

        # Schema validation
        try:
            jsonschema.validate(instance=result, schema=schema)
        except jsonschema.ValidationError as exc:
            pytest.fail(
                f"Output does not conform to a2a-verification-result schema: "
                f"{exc.message}\n\nActual output keys: {sorted(result.keys())}"
            )

        # Core fields
        assert result.get("status") == expected["status"], (
            f"status: expected {expected['status']!r}, got {result.get('status')!r}"
        )
        assert result.get("valid") == expected["valid"]
        assert result.get("signerId") == expected["signerId"]
        assert result.get("artifactType") == expected["artifactType"]
        assert result.get("parentSignaturesValid") == expected["parentSignaturesValid"]

        # Trust fields
        assert "trustLevel" in result, (
            "Foreign-verified fixture expects 'trustLevel' in output"
        )
        assert result.get("trustLevel") == expected.get("trustLevel")

        assert "trustAssessment" in result, (
            "Foreign-verified fixture expects 'trustAssessment' in output"
        )
        trust = result.get("trustAssessment", {})
        expected_trust = expected.get("trustAssessment", {})
        assert trust.get("allowed") == expected_trust.get("allowed")
        assert trust.get("trustLevel") == expected_trust.get("trustLevel")
        assert trust.get("policy") == expected_trust.get("policy")
        assert trust.get("jacsRegistered") == expected_trust.get("jacsRegistered")

        # Parent verification results structure
        expected_parents = expected.get("parentVerificationResults", [])
        actual_parents = result.get("parentVerificationResults", [])
        assert len(actual_parents) == len(expected_parents), (
            f"parentVerificationResults length: expected {len(expected_parents)}, "
            f"got {len(actual_parents)}"
        )
        if actual_parents and expected_parents:
            first_parent = actual_parents[0]
            expected_first = expected_parents[0]
            # Check parent result uses camelCase fields per schema
            assert "artifactId" in first_parent, (
                "Parent result must use 'artifactId' (camelCase)"
            )
            assert "signerId" in first_parent, (
                "Parent result must use 'signerId' (camelCase)"
            )
            assert "status" in first_parent, (
                "Parent result must include 'status' field"
            )
            assert "verified" in first_parent, (
                "Parent result must include 'verified' boolean"
            )

    def test_contract_unverified_vs_invalid(self, schema: Dict[str, Any]):
        """Verify that ``Unverified`` and ``Invalid`` produce distinct status
        values matching their respective fixture structures.

        ``Unverified`` means the public key was not available to attempt
        verification.  ``Invalid`` means the key was available but the
        signature did not match.

        This test is expected to fail until TASK_007 implements the status enum.

        Fixtures: foreign_unverified.json, invalid_signature.json
        """
        unverified_expected = _load_fixture("foreign_unverified")
        invalid_expected = _load_fixture("invalid_signature")

        # Both cases: verification fails, but for different reasons
        integration = _make_integration(verify_succeeds=False)

        # -- Unverified case --
        unverified_wrapped = _make_wrapped_artifact(
            signer_id=unverified_expected["signerId"],
            signer_version=unverified_expected["signerVersion"],
            artifact_type=unverified_expected["artifactType"],
            timestamp=unverified_expected["timestamp"],
            artifact=unverified_expected["originalArtifact"],
        )
        unverified_result = integration.verify_wrapped_artifact(unverified_wrapped)

        # -- Invalid case --
        invalid_wrapped = _make_wrapped_artifact(
            signer_id=invalid_expected["signerId"],
            signer_version=invalid_expected["signerVersion"],
            artifact_type=invalid_expected["artifactType"],
            timestamp=invalid_expected["timestamp"],
            artifact=invalid_expected["originalArtifact"],
        )
        invalid_result = integration.verify_wrapped_artifact(invalid_wrapped)

        # Both must be invalid
        assert unverified_result.get("valid") is False, (
            "Unverified artifact must have valid=False"
        )
        assert invalid_result.get("valid") is False, (
            "Invalid artifact must have valid=False"
        )

        # They must have distinct status structures
        unverified_status = unverified_result.get("status")
        invalid_status = invalid_result.get("status")

        assert unverified_status is not None, (
            "Unverified result must have a 'status' field"
        )
        assert invalid_status is not None, (
            "Invalid result must have a 'status' field"
        )

        # Unverified: status should be {"Unverified": {"reason": "..."}}
        assert isinstance(unverified_status, dict), (
            f"Unverified status must be a dict (got {type(unverified_status).__name__})"
        )
        assert "Unverified" in unverified_status, (
            f"Unverified status dict must contain 'Unverified' key, "
            f"got keys: {list(unverified_status.keys()) if isinstance(unverified_status, dict) else 'N/A'}"
        )

        # Invalid: status should be {"Invalid": {"reason": "..."}}
        assert isinstance(invalid_status, dict), (
            f"Invalid status must be a dict (got {type(invalid_status).__name__})"
        )
        assert "Invalid" in invalid_status, (
            f"Invalid status dict must contain 'Invalid' key, "
            f"got keys: {list(invalid_status.keys()) if isinstance(invalid_status, dict) else 'N/A'}"
        )

        # The two status values must be structurally different
        assert unverified_status != invalid_status, (
            "Unverified and Invalid must produce distinct status values"
        )

    def test_contract_trust_blocked(self, schema: Dict[str, Any]):
        """Verify Python output for a trust-blocked artifact matches the
        ``trust_blocked.json`` fixture structure.

        Expected: status=Invalid (due to policy), trustAssessment.allowed=false.
        This test is expected to fail until TASK_008/011 align the trust output.

        Fixture: fixtures/a2a_contract/trust_blocked.json
        """
        expected = _load_fixture("trust_blocked")

        integration = _make_integration(verify_succeeds=False)
        wrapped = _make_wrapped_artifact(
            signer_id=expected["signerId"],
            signer_version=expected["signerVersion"],
            artifact_type=expected["artifactType"],
            timestamp=expected["timestamp"],
            artifact=expected["originalArtifact"],
        )

        result = integration.verify_wrapped_artifact(wrapped)

        # Schema validation
        try:
            jsonschema.validate(instance=result, schema=schema)
        except jsonschema.ValidationError as exc:
            pytest.fail(
                f"Output does not conform to a2a-verification-result schema: "
                f"{exc.message}\n\nActual output keys: {sorted(result.keys())}"
            )

        # Core assertions
        assert result.get("valid") == expected["valid"]
        assert result.get("signerId") == expected["signerId"]

        # Trust assessment must indicate blocked
        assert "trustAssessment" in result, (
            "Trust-blocked fixture expects 'trustAssessment' in output"
        )
        trust = result.get("trustAssessment", {})
        expected_trust = expected.get("trustAssessment", {})
        assert trust.get("allowed") is False, (
            "trustAssessment.allowed must be False for blocked agents"
        )
        assert trust.get("policy") == expected_trust.get("policy"), (
            f"policy: expected {expected_trust.get('policy')!r}, "
            f"got {trust.get('policy')!r}"
        )

    def test_all_fixtures_conform_to_schema(self, schema: Dict[str, Any]):
        """Meta-test: all fixture files themselves must be valid against the
        shared schema.

        This test validates the test data, not the wrapper output.  It should
        pass immediately since Task 001 created conforming fixtures.
        """
        fixture_names = [
            "self_signed_verified",
            "foreign_verified",
            "foreign_unverified",
            "invalid_signature",
            "trust_blocked",
        ]

        for name in fixture_names:
            fixture = _load_fixture(name)
            try:
                jsonschema.validate(instance=fixture, schema=schema)
            except jsonschema.ValidationError as exc:
                pytest.fail(
                    f"Fixture '{name}.json' does not conform to schema: {exc.message}"
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
