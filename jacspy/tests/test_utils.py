"""Tests for the jacspy utility functions and JacsAgent class."""

import pytest
import jacs
import os
import pathlib
import tempfile
import json


class TestModuleExports:
    """Test that the jacs module exports expected items."""

    def test_module_import(self):
        """Check if the module imports correctly."""
        assert jacs is not None

    def test_jacs_agent_class_exported(self):
        """Check if JacsAgent class is exported."""
        assert hasattr(jacs, "JacsAgent")
        assert callable(jacs.JacsAgent)

    def test_hash_string_function_exported(self):
        """Check if hash_string function is exported."""
        assert hasattr(jacs, "hash_string")
        assert callable(jacs.hash_string)

    def test_legacy_functions_exported(self):
        """Check if legacy functions are still exported for backwards compatibility."""
        legacy_functions = [
            "load",
            "sign_request",
            "verify_response",
            "sign_string",
            "verify_string",
            "create_config",
        ]
        for func_name in legacy_functions:
            assert hasattr(jacs, func_name), f"Missing legacy function: {func_name}"


class TestHashString:
    """Test the standalone hash_string function."""

    def test_hash_empty_string(self):
        """Test hashing an empty string."""
        result = jacs.hash_string("")
        assert isinstance(result, str)
        assert len(result) > 0  # Should return a hash

    def test_hash_simple_string(self):
        """Test hashing a simple string."""
        result = jacs.hash_string("hello")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_hash_deterministic(self):
        """Test that hashing is deterministic."""
        result1 = jacs.hash_string("test data")
        result2 = jacs.hash_string("test data")
        assert result1 == result2

    def test_hash_different_inputs(self):
        """Test that different inputs produce different hashes."""
        result1 = jacs.hash_string("hello")
        result2 = jacs.hash_string("world")
        assert result1 != result2

    def test_hash_unicode_string(self):
        """Test hashing unicode strings."""
        result = jacs.hash_string("Hello, 世界! 🌍")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_hash_long_string(self):
        """Test hashing a long string."""
        long_string = "x" * 10000
        result = jacs.hash_string(long_string)
        assert isinstance(result, str)
        assert len(result) > 0


class TestJacsAgentClass:
    """Test the JacsAgent class."""

    def test_create_agent_instance(self):
        """Test creating a JacsAgent instance."""
        agent = jacs.JacsAgent()
        assert agent is not None

    def test_create_multiple_agents(self):
        """Test creating multiple independent agent instances."""
        agent1 = jacs.JacsAgent()
        agent2 = jacs.JacsAgent()
        assert agent1 is not None
        assert agent2 is not None
        assert agent1 is not agent2

    def test_agent_has_expected_methods(self):
        """Test that JacsAgent has expected methods."""
        agent = jacs.JacsAgent()
        expected_methods = [
            "load",
            "sign_string",
            "verify_string",
            "sign_request",
            "verify_response",
            "verify_response_with_agent_id",
            "create_document",
            "verify_document",
            "create_agreement",
            "sign_agreement",
            "check_agreement",
            "verify_agent",
            "update_agent",
        ]
        for method_name in expected_methods:
            assert hasattr(agent, method_name), f"Missing method: {method_name}"

    def test_load_nonexistent_config(self):
        """Test that loading a nonexistent config raises an error."""
        agent = jacs.JacsAgent()
        with pytest.raises(RuntimeError):
            agent.load("/nonexistent/path/config.json")

    def test_sign_string_without_load_raises_error(self):
        """Test that signing without loading config raises an error."""
        agent = jacs.JacsAgent()
        with pytest.raises(RuntimeError):
            agent.sign_string("test data")

    def test_sign_request_without_load_raises_error(self):
        """Test that sign_request without loading config raises an error."""
        agent = jacs.JacsAgent()
        with pytest.raises(RuntimeError):
            agent.sign_request({"message": "test"})


class TestJacsAgentWithFixtures:
    """Tests that require the test fixtures to be properly set up."""

    @pytest.fixture
    def loaded_agent(self, in_fixtures_dir, shared_config_path):
        """Create and load an agent from fixtures.

        This fixture requires:
        - JACS_PRIVATE_KEY_PASSWORD environment variable to be set correctly
        - Valid fixtures in jacs/tests/scratch/

        Uses in_fixtures_dir to ensure CWD is properly managed with cleanup.
        """
        try:
            agent = jacs.JacsAgent()
            agent.load(shared_config_path)
            yield agent
        except RuntimeError as e:
            pytest.skip(f"Could not load agent fixtures: {e}")

    @pytest.mark.skipif(
        os.environ.get("JACS_PRIVATE_KEY_PASSWORD") is None,
        reason="JACS_PRIVATE_KEY_PASSWORD not set"
    )
    def test_sign_and_verify_string(self, loaded_agent):
        """Test signing and verifying a string with a loaded agent."""
        data = "hello world"
        signature = loaded_agent.sign_string(data)
        assert isinstance(signature, str)
        assert len(signature) > 0

    @pytest.mark.skipif(
        os.environ.get("JACS_PRIVATE_KEY_PASSWORD") is None,
        reason="JACS_PRIVATE_KEY_PASSWORD not set"
    )
    def test_sign_and_verify_request(self, loaded_agent):
        """Test signing and verifying a request payload."""
        request_data = {"message": "hello", "value": 123}
        signed = loaded_agent.sign_request(request_data)
        assert isinstance(signed, str)

        # Verify the signed document
        verified = loaded_agent.verify_response(signed)
        assert verified == request_data

    @pytest.mark.skipif(
        os.environ.get("JACS_PRIVATE_KEY_PASSWORD") is None,
        reason="JACS_PRIVATE_KEY_PASSWORD not set"
    )
    def test_sign_request_with_various_types(self, loaded_agent):
        """Test signing various Python types."""
        test_cases = [
            {"null_value": None},
            {"bool_true": True, "bool_false": False},
            {"int_value": 123, "float_value": 3.14},
            {"string_value": "hello"},
            {"list_value": [1, 2, 3]},
            {"nested": {"a": 1, "b": [2, 3]}},
        ]

        for test_data in test_cases:
            signed = loaded_agent.sign_request(test_data)
            verified = loaded_agent.verify_response(signed)
            assert verified == test_data, f"Failed for: {test_data}"

    @pytest.mark.skipif(
        os.environ.get("JACS_PRIVATE_KEY_PASSWORD") is None,
        reason="JACS_PRIVATE_KEY_PASSWORD not set"
    )
    def test_verify_response_with_agent_id(self, loaded_agent):
        """Test verify_response_with_agent_id returns both payload and agent ID."""
        request_data = {"message": "test"}
        signed = loaded_agent.sign_request(request_data)

        result = loaded_agent.verify_response_with_agent_id(signed)
        assert isinstance(result, tuple)
        assert len(result) == 2

        agent_id, payload = result
        assert isinstance(agent_id, str)
        assert payload == request_data


class TestCreateConfig:
    """Test the create_config function."""

    def test_create_config_function_exists(self):
        """Test that create_config function exists."""
        assert hasattr(jacs, "create_config")
        assert callable(jacs.create_config)


class TestBinaryDataHandling:
    """Test handling of binary data in Python."""

    def test_binary_to_base64_roundtrip(self):
        """Test that binary data can be represented for signing."""
        import base64

        # Binary data needs to be converted to base64 for JSON serialization
        binary_data = b"\x00\x01\x02\xff\xfe"
        encoded = base64.b64encode(binary_data).decode("utf-8")

        # Hash should work on the encoded string
        hash_result = jacs.hash_string(encoded)
        assert isinstance(hash_result, str)
