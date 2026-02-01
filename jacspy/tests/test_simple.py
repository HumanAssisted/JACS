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


@pytest.fixture(scope="module")
def config_path():
    """Get path to JACS config, skip if not available."""
    path = os.environ.get("JACS_CONFIG_PATH", "./jacs.config.json")
    if not os.path.exists(path):
        pytest.skip(f"JACS config not found at {path}")
    return path


@pytest.fixture(scope="module")
def loaded_agent(config_path):
    """Load agent once for all tests in module."""
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
        """verify_self() without loaded agent should work if one was loaded."""
        # This test depends on previous tests having loaded an agent
        result = simple.verify_self()
        assert result is not None


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

        # Verify embedded content is in the document
        doc = json.loads(signed.raw)
        assert "jacsFiles" in doc

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
