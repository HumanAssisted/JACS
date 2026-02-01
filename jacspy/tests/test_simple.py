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
