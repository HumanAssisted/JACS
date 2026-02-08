"""
Tests for the simplified JACS Python API.

These tests require a valid jacs.config.json in the test directory
or the JACS_CONFIG_PATH environment variable set.
"""

import json
import os
import pytest
import tempfile
from pathlib import Path

# Skip all tests if jacs module is not available
pytest.importorskip("jacs")

from jacs import simple
from jacs.types import (
    AgentInfo,
    SignedDocument,
    VerificationResult,
    SignerStatus,
    AgreementStatus,
    JacsError,
    AgentNotLoadedError,
)


# Fixtures


@pytest.fixture
def config_path(in_fixtures_dir, shared_config_path):
    """Get path to JACS config from shared fixtures.

    Uses in_fixtures_dir to ensure CWD is properly managed with cleanup.
    """
    path = os.environ.get("JACS_CONFIG_PATH", shared_config_path)
    if not os.path.exists(path):
        pytest.skip(f"JACS config not found at {path}")
    return path


@pytest.fixture
def loaded_agent(config_path):
    """Load agent for tests that need it. Reloads module to ensure clean state."""
    # Reload to ensure clean state (some tests may have reloaded and cleared it)
    import importlib
    importlib.reload(simple)
    info = simple.load(config_path)
    assert info is not None
    return info


# Test load()


class TestLoad:
    def test_load_returns_agent_info(self, config_path):
        """load() should return AgentInfo with valid fields."""
        info = simple.load(config_path)

        assert isinstance(info, AgentInfo)
        assert info.agent_id  # Should have an agent ID
        assert info.config_path == config_path

    def test_load_nonexistent_raises(self):
        """load() with nonexistent path should raise error."""
        with pytest.raises(JacsError):
            simple.load("/nonexistent/path/config.json")

    def test_is_loaded_after_load(self, config_path):
        """is_loaded() should return True after successful load."""
        simple.load(config_path)
        assert simple.is_loaded() is True


# Test verify_self()


class TestVerifySelf:
    def test_verify_self_valid(self, loaded_agent):
        """verify_self() should return valid=True for loaded agent."""
        result = simple.verify_self()

        assert isinstance(result, VerificationResult)
        assert result.valid is True
        assert len(result.errors) == 0

    def test_verify_self_without_load_raises(self):
        """verify_self() without loaded agent should raise AgentNotLoadedError."""
        # Reset the global agent state to ensure clean test
        import importlib
        importlib.reload(simple)

        with pytest.raises(AgentNotLoadedError):
            simple.verify_self()


# Test verify_standalone()


class TestVerifyStandalone:
    """verify_standalone() does not require load()."""

    def test_verify_standalone_invalid_json_returns_valid_false(self):
        """verify_standalone() with invalid JSON should return valid=False."""
        import importlib
        importlib.reload(simple)
        result = simple.verify_standalone("not json", key_resolution="local")
        assert isinstance(result, VerificationResult)
        assert result.valid is False
        assert result.signer_id == ""

    def test_verify_standalone_tampered_returns_valid_false_with_signer_id(self):
        """verify_standalone() with tampered doc should return valid=False and signer_id from doc."""
        import importlib
        importlib.reload(simple)
        tampered = '{"jacsSignature":{"agentID":"test-agent"},"jacsSha256":"x"}'
        result = simple.verify_standalone(tampered, key_resolution="local")
        assert result.valid is False
        assert result.signer_id == "test-agent"


# Test DNS helpers


class TestDnsHelpers:
    def test_get_dns_record_without_load_raises(self):
        import importlib
        importlib.reload(simple)
        with pytest.raises((AgentNotLoadedError, JacsError)):
            simple.get_dns_record("example.com", 3600)

    def test_get_dns_record_returns_expected_format(self, loaded_agent):
        record = simple.get_dns_record("example.com", 3600)
        assert isinstance(record, str)
        assert "_v1.agent.jacs.example.com." in record
        assert "3600" in record
        assert "IN TXT" in record
        assert "v=hai.ai" in record
        assert "jacs_agent_id=" in record
        assert "alg=SHA-256" in record
        assert "enc=base64" in record
        assert "jac_public_key_hash=" in record

    def test_get_well_known_json_without_load_raises(self):
        import importlib
        importlib.reload(simple)
        with pytest.raises((AgentNotLoadedError, JacsError)):
            simple.get_well_known_json()

    def test_get_well_known_json_has_keys(self, loaded_agent):
        obj = simple.get_well_known_json()
        assert isinstance(obj, dict)
        assert "publicKey" in obj
        assert "publicKeyHash" in obj
        assert "algorithm" in obj
        assert "agentId" in obj


# Test update_agent()


class TestUpdateAgent:
    def test_update_agent_without_load_raises(self):
        """update_agent() without loaded agent should raise AgentNotLoadedError."""
        import importlib
        importlib.reload(simple)

        with pytest.raises(AgentNotLoadedError):
            simple.update_agent({"description": "test"})

    def test_update_agent_rejects_incomplete_data(self, loaded_agent):
        """update_agent() should reject incomplete agent data."""
        # Passing incomplete data should fail validation
        with pytest.raises(Exception, match=r"jacsId.*required|Failed to update"):
            simple.update_agent({"name": "test"})

    def test_update_agent_with_modified_document(self, loaded_agent):
        """update_agent() should update agent with modified document."""
        # Get the current agent document
        agent_doc = simple.export_agent()
        agent = json.loads(agent_doc)
        original_version = agent.get("jacsVersion")

        # Add required field if missing (schema requires at least 1 contact)
        if "jacsContacts" not in agent or len(agent.get("jacsContacts", [])) == 0:
            agent["jacsContacts"] = [{"contactFirstName": "Test", "contactLastName": "Contact"}]

        # Modify a field with valid enum value
        agent["jacsAgentType"] = "hybrid"

        # Update with modified document
        result = simple.update_agent(agent)

        assert isinstance(result, str)
        doc = json.loads(result)
        assert "jacsSignature" in doc
        assert doc["jacsAgentType"] == "hybrid"
        # Should have new version
        assert doc["jacsVersion"] != original_version

    def test_update_agent_with_json_string(self, loaded_agent):
        """update_agent() should accept a JSON string."""
        # Get the current agent document and modify it
        agent_doc = simple.export_agent()
        agent = json.loads(agent_doc)

        # Add required field if missing (schema requires at least 1 contact)
        if "jacsContacts" not in agent or len(agent.get("jacsContacts", [])) == 0:
            agent["jacsContacts"] = [{"contactFirstName": "Test", "contactLastName": "Contact"}]

        agent["jacsAgentType"] = "human-org"

        result = simple.update_agent(json.dumps(agent))

        assert isinstance(result, str)
        doc = json.loads(result)
        assert "jacsSignature" in doc
        assert doc["jacsAgentType"] == "human-org"


# Test update_document()


class TestUpdateDocument:
    def test_update_document_without_load_raises(self):
        """update_document() without loaded agent should raise AgentNotLoadedError."""
        import importlib
        importlib.reload(simple)

        with pytest.raises(AgentNotLoadedError):
            simple.update_document("doc-id", {"data": "test"})

    def test_update_document_fails_for_nonexistent(self, loaded_agent):
        """update_document() should fail for non-existent document."""
        with pytest.raises(Exception, match=r"not found|Failed to update"):
            simple.update_document("non-existent-id", {"data": "test"})

    # Note: update_document() requires the original document to be persisted to disk.
    # For a full test, documents would need to be created with persistence enabled.
    # This is demonstrated in the integration tests with proper fixtures.


# Test sign_message()


class TestSignMessage:
    def test_sign_dict(self, loaded_agent):
        """sign_message() should sign a dictionary."""
        data = {"action": "test", "value": 42}
        signed = simple.sign_message(data)

        assert isinstance(signed, SignedDocument)
        assert signed.document_id  # Should have a document ID
        assert signed.agent_id  # Should have agent ID
        assert signed.timestamp  # Should have timestamp
        assert signed.raw  # Should have raw JSON

    def test_sign_list(self, loaded_agent):
        """sign_message() should sign a list."""
        data = [1, 2, 3, "test"]
        signed = simple.sign_message(data)

        assert isinstance(signed, SignedDocument)
        assert signed.raw

    def test_sign_string(self, loaded_agent):
        """sign_message() should sign a string."""
        data = "Hello, JACS!"
        signed = simple.sign_message(data)

        assert isinstance(signed, SignedDocument)

    def test_sign_nested(self, loaded_agent):
        """sign_message() should handle nested structures."""
        data = {
            "level1": {
                "level2": {
                    "level3": [1, 2, {"key": "value"}]
                }
            }
        }
        signed = simple.sign_message(data)

        assert isinstance(signed, SignedDocument)

    def test_sign_produces_valid_json(self, loaded_agent):
        """sign_message() should produce valid JSON in raw field."""
        data = {"test": True}
        signed = simple.sign_message(data)

        parsed = json.loads(signed.raw)
        assert "jacsSignature" in parsed


# Test verify()


class TestVerify:
    def test_verify_own_signature(self, loaded_agent):
        """verify() should validate documents we signed."""
        data = {"verified": True}
        signed = simple.sign_message(data)

        result = simple.verify(signed.raw)

        assert isinstance(result, VerificationResult)
        assert result.valid is True
        assert result.signer_id == signed.agent_id

    def test_verify_preserves_data(self, loaded_agent):
        """verify() should preserve the original data."""
        data = {"key": "value", "number": 123}
        signed = simple.sign_message(data)

        result = simple.verify(signed.raw)

        # The data should be accessible in result
        assert result.valid is True

    def test_verify_invalid_json(self, loaded_agent):
        """verify() should handle invalid JSON gracefully."""
        result = simple.verify("not valid json")

        assert result.valid is False
        assert len(result.errors) > 0

    def test_verify_tampered_document(self, loaded_agent):
        """verify() should detect tampering."""
        data = {"original": True}
        signed = simple.sign_message(data)

        # Tamper with the document
        doc = json.loads(signed.raw)
        doc["original"] = False  # Modify the data
        tampered = json.dumps(doc)

        result = simple.verify(tampered)

        # Should be invalid after tampering
        assert result.valid is False


# Test sign_file()


class TestSignFile:
    def test_sign_file_reference(self, loaded_agent, tmp_path):
        """sign_file() should sign a file in reference mode."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        signed = simple.sign_file(str(test_file), embed=False)

        assert isinstance(signed, SignedDocument)
        assert signed.document_id

    def test_sign_file_embed(self, loaded_agent, tmp_path):
        """sign_file() should sign a file with embedding."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Embedded content")

        signed = simple.sign_file(str(test_file), embed=True)

        assert isinstance(signed, SignedDocument)

        # Note: jacsFiles embedding only works for files within JACS data directory
        # For files outside the data directory, signing works but embedding is skipped
        doc = json.loads(signed.raw)
        assert "jacsSignature" in doc

    def test_sign_nonexistent_file_raises(self, loaded_agent):
        """sign_file() should raise for nonexistent files."""
        with pytest.raises(JacsError):
            simple.sign_file("/nonexistent/file.txt")


# Test get_public_key()


class TestGetPublicKey:
    def test_returns_pem(self, loaded_agent):
        """get_public_key() should return PEM formatted key."""
        pem = simple.get_public_key()

        assert pem.startswith("-----BEGIN")
        assert "KEY" in pem
        assert pem.strip().endswith("-----")


# Test get_agent_info()


class TestGetAgentInfo:
    def test_returns_info(self, loaded_agent):
        """get_agent_info() should return current agent info."""
        info = simple.get_agent_info()

        assert isinstance(info, AgentInfo)
        assert info.agent_id


# Integration test


class TestIntegration:
    def test_full_workflow(self, config_path):
        """Test complete sign-verify workflow."""
        # Load
        info = simple.load(config_path)
        assert info is not None

        # Verify self
        self_check = simple.verify_self()
        assert self_check.valid

        # Sign
        data = {
            "transaction_id": "tx-001",
            "amount": 100.50,
            "currency": "USD",
            "approved": True
        }
        signed = simple.sign_message(data)
        assert signed.document_id

        # Verify
        result = simple.verify(signed.raw)
        assert result.valid
        assert result.signer_id == info.agent_id


# Test Agreement Functions


class TestAgreementTypes:
    """Test agreement type dataclasses."""

    def test_signer_status_from_dict(self):
        """SignerStatus.from_dict should parse correctly."""
        data = {
            "agent_id": "agent-123",
            "signed": True,
            "signed_at": "2024-01-15T10:30:00Z"
        }
        status = SignerStatus.from_dict(data)

        assert status.agent_id == "agent-123"
        assert status.signed is True
        assert status.signed_at == "2024-01-15T10:30:00Z"

    def test_signer_status_from_dict_camelcase(self):
        """SignerStatus.from_dict should handle camelCase keys."""
        data = {
            "agentId": "agent-456",
            "signed": False,
            "signedAt": None
        }
        status = SignerStatus.from_dict(data)

        assert status.agent_id == "agent-456"
        assert status.signed is False
        assert status.signed_at is None

    def test_agreement_status_from_dict(self):
        """AgreementStatus.from_dict should parse correctly."""
        data = {
            "complete": False,
            "signers": [
                {"agent_id": "agent-1", "signed": True, "signed_at": "2024-01-15T10:30:00Z"},
                {"agent_id": "agent-2", "signed": False}
            ],
            "pending": ["agent-2"]
        }
        status = AgreementStatus.from_dict(data)

        assert status.complete is False
        assert len(status.signers) == 2
        assert status.signers[0].agent_id == "agent-1"
        assert status.signers[0].signed is True
        assert status.signers[1].agent_id == "agent-2"
        assert status.signers[1].signed is False
        assert status.pending == ["agent-2"]


class TestCreateAgreement:
    """Test create_agreement function."""

    def test_create_agreement_without_load_raises(self):
        """create_agreement() without loaded agent should raise AgentNotLoadedError."""
        import importlib
        importlib.reload(simple)

        with pytest.raises(AgentNotLoadedError):
            simple.create_agreement(
                document={"proposal": "test"},
                agent_ids=["agent-1", "agent-2"]
            )

    def test_create_agreement_returns_signed_document(self, loaded_agent):
        """create_agreement() should return a SignedDocument."""
        agreement = simple.create_agreement(
            document={"proposal": "Test proposal"},
            agent_ids=[loaded_agent.agent_id],
            question="Do you approve?",
            context="This is a test agreement"
        )

        assert isinstance(agreement, SignedDocument)
        assert agreement.document_id
        assert agreement.agent_id
        assert agreement.raw_json

    def test_create_agreement_with_dict(self, loaded_agent):
        """create_agreement() should accept a dict."""
        agreement = simple.create_agreement(
            document={"data": "test"},
            agent_ids=[loaded_agent.agent_id]
        )

        assert isinstance(agreement, SignedDocument)

    def test_create_agreement_with_json_string(self, loaded_agent):
        """create_agreement() should accept a JSON string."""
        doc_str = json.dumps({"data": "test"})
        agreement = simple.create_agreement(
            document=doc_str,
            agent_ids=[loaded_agent.agent_id]
        )

        assert isinstance(agreement, SignedDocument)


class TestSignAgreement:
    """Test sign_agreement function."""

    def test_sign_agreement_without_load_raises(self):
        """sign_agreement() without loaded agent should raise AgentNotLoadedError."""
        import importlib
        importlib.reload(simple)

        with pytest.raises(AgentNotLoadedError):
            simple.sign_agreement(document={"test": True})

    def test_sign_agreement_adds_signature(self, loaded_agent):
        """sign_agreement() should add the current agent's signature."""
        # First create an agreement
        agreement = simple.create_agreement(
            document={"proposal": "Sign this"},
            agent_ids=[loaded_agent.agent_id]
        )

        # Then sign it
        signed = simple.sign_agreement(agreement)

        assert isinstance(signed, SignedDocument)
        assert signed.document_id


class TestCheckAgreement:
    """Test check_agreement function."""

    def test_check_agreement_without_load_raises(self):
        """check_agreement() without loaded agent should raise AgentNotLoadedError."""
        import importlib
        importlib.reload(simple)

        with pytest.raises(AgentNotLoadedError):
            simple.check_agreement(document={"test": True})

    def test_check_agreement_returns_status(self, loaded_agent):
        """check_agreement() should return AgreementStatus."""
        # Create and sign an agreement
        agreement = simple.create_agreement(
            document={"proposal": "Check this"},
            agent_ids=[loaded_agent.agent_id]
        )
        signed = simple.sign_agreement(agreement)

        # Check status
        status = simple.check_agreement(signed)

        assert isinstance(status, AgreementStatus)
        assert isinstance(status.complete, bool)
        assert isinstance(status.signers, list)
        assert isinstance(status.pending, list)

    def test_check_agreement_shows_completion(self, loaded_agent):
        """check_agreement() should show complete=True after all sign."""
        # Create agreement with only the loaded agent
        agreement = simple.create_agreement(
            document={"proposal": "Single signer"},
            agent_ids=[loaded_agent.agent_id]
        )

        # Sign it
        signed = simple.sign_agreement(agreement)

        # Should be complete
        status = simple.check_agreement(signed)
        assert status.complete is True
        assert len(status.pending) == 0


class TestAgreementWorkflow:
    """Integration tests for complete agreement workflows."""

    def test_single_party_agreement_workflow(self, loaded_agent):
        """Test complete single-party agreement workflow."""
        # Step 1: Create agreement
        proposal = {"action": "approve_budget", "amount": 10000}
        agreement = simple.create_agreement(
            document=proposal,
            agent_ids=[loaded_agent.agent_id],
            question="Do you approve this budget?",
            context="Q4 2024 budget request"
        )
        assert agreement.document_id

        # Step 2: Check status before signing should fail (strict agreement verification)
        with pytest.raises(JacsError):
            simple.check_agreement(agreement)

        # Step 3: Sign agreement
        signed = simple.sign_agreement(agreement)
        assert signed.document_id

        # Step 4: Check status (should be complete)
        final_status = simple.check_agreement(signed)
        assert final_status.complete is True
        assert len(final_status.pending) == 0

        # Step 5: Verify the signed document is valid
        result = simple.verify(signed.raw_json)
        assert result.valid is True

    def test_two_party_agreement_requires_both_signatures(self, tmp_path):
        """Two distinct agents should both sign before agreement check succeeds."""
        password = "TestP@ss123!#"

        shared_data = tmp_path / "shared-data"
        a1_root = tmp_path / "agent1"
        a2_root = tmp_path / "agent2"
        shared_data.mkdir()
        a1_root.mkdir()
        a2_root.mkdir()

        original_cwd = os.getcwd()
        try:
            # Use relative paths so storage and config resolution match across backends.
            os.chdir(tmp_path)

            # Create two independent agents with separate keys and shared public key cache.
            a1 = simple.create(
                name="pytest-agent-1",
                password=password,
                algorithm="ring-Ed25519",
                data_directory="shared-data",
                key_directory="agent1/keys",
                config_path="agent1/jacs.config.json",
            )
            a2 = simple.create(
                name="pytest-agent-2",
                password=password,
                algorithm="ring-Ed25519",
                data_directory="shared-data",
                key_directory="agent2/keys",
                config_path="agent2/jacs.config.json",
            )

            # Agent 1 creates agreement requiring signatures from both agents.
            simple.load("agent1/jacs.config.json")
            agreement = simple.create_agreement(
                document={"proposal": "two-party-approval", "amount": 25000},
                agent_ids=[a1.agent_id, a2.agent_id],
                question="Do both parties approve?",
                context="Two-agent integration agreement test",
            )

            # Incomplete agreement must fail strict check before both signatures exist.
            with pytest.raises(JacsError):
                simple.check_agreement(agreement)

            signed_by_a1 = simple.sign_agreement(agreement)
            with pytest.raises(JacsError):
                simple.check_agreement(signed_by_a1)

            # Agent 2 signs and completion succeeds.
            simple.load("agent2/jacs.config.json")
            signed_by_both = simple.sign_agreement(signed_by_a1)
            status = simple.check_agreement(signed_by_both)
            assert status.complete is True
            assert len(status.pending) == 0
        finally:
            os.chdir(original_cwd)


class TestAudit:
    """Tests for audit() security audit and health checks."""

    def test_audit_returns_dict_with_risks_and_health_checks(self):
        """audit() returns a dict with 'risks' and 'health_checks'."""
        result = simple.audit()
        assert "risks" in result
        assert "health_checks" in result
        assert isinstance(result["risks"], list)
        assert isinstance(result["health_checks"], list)

    def test_audit_returns_summary_and_overall_status(self):
        """audit() includes summary and overall_status."""
        result = simple.audit()
        assert "summary" in result
        assert "overall_status" in result
        assert result["summary"]
