"""
Tests for fetch_remote_key functionality.

These tests verify the Python SDK's ability to fetch public keys from
HAI's key distribution service.
"""

import os
import sys
import unittest

# Add parent directory for development import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jacs.types import PublicKeyInfo, KeyNotFoundError, NetworkError, JacsError
import jacs.simple as jacs


class TestFetchRemoteKey(unittest.TestCase):
    """Tests for the fetch_remote_key function."""

    def test_function_exists(self):
        """Verify the function is exported and callable."""
        self.assertTrue(hasattr(jacs, 'fetch_remote_key'))
        self.assertTrue(callable(jacs.fetch_remote_key))

    def test_types_exist(self):
        """Verify the associated types are available."""
        self.assertTrue(PublicKeyInfo is not None)
        self.assertTrue(issubclass(KeyNotFoundError, JacsError))
        self.assertTrue(issubclass(NetworkError, JacsError))

    def test_public_key_info_dataclass(self):
        """Test that PublicKeyInfo can be instantiated."""
        info = PublicKeyInfo(
            public_key=b"test_key_bytes",
            algorithm="ed25519",
            public_key_hash="abc123",
            agent_id="test-agent",
            version="1",
        )
        self.assertEqual(info.public_key, b"test_key_bytes")
        self.assertEqual(info.algorithm, "ed25519")
        self.assertEqual(info.public_key_hash, "abc123")
        self.assertEqual(info.agent_id, "test-agent")
        self.assertEqual(info.version, "1")

    def test_public_key_info_from_dict(self):
        """Test PublicKeyInfo.from_dict factory method."""
        data = {
            "public_key": b"key_bytes",
            "algorithm": "rsa-pss-sha256",
            "public_key_hash": "hash123",
            "agent_id": "agent-1",
            "version": "latest",
        }
        info = PublicKeyInfo.from_dict(data)
        self.assertEqual(info.public_key, b"key_bytes")
        self.assertEqual(info.algorithm, "rsa-pss-sha256")

    def test_network_error_on_unreachable_server(self):
        """Test that NetworkError is raised when server is unreachable."""
        # Use a localhost URL that's not running
        os.environ["HAI_KEYS_BASE_URL"] = "http://127.0.0.1:19999"
        try:
            with self.assertRaises(NetworkError):
                jacs.fetch_remote_key(
                    "550e8400-e29b-41d4-a716-446655440000",
                    "550e8400-e29b-41d4-a716-446655440001",
                )
        finally:
            # Clean up environment
            if "HAI_KEYS_BASE_URL" in os.environ:
                del os.environ["HAI_KEYS_BASE_URL"]

    def test_default_version_is_latest(self):
        """Test that version defaults to 'latest'."""
        # This tests the function signature, not a live call
        import inspect
        sig = inspect.signature(jacs.fetch_remote_key)
        version_param = sig.parameters.get("version")
        self.assertIsNotNone(version_param)
        self.assertEqual(version_param.default, "latest")


class TestFetchRemoteKeyIntegration(unittest.TestCase):
    """Integration tests that require a running HAI key service.

    These tests are skipped by default. To run them, set the environment
    variable HAI_KEYS_INTEGRATION_TEST=1 and ensure HAI_KEYS_BASE_URL
    points to a running key service.
    """

    def setUp(self):
        if not os.environ.get("HAI_KEYS_INTEGRATION_TEST"):
            self.skipTest("Set HAI_KEYS_INTEGRATION_TEST=1 to run integration tests")

    def test_fetch_valid_key(self):
        """Test fetching a valid key from the service."""
        # This test requires a known agent ID that exists in the key service
        agent_id = os.environ.get("TEST_AGENT_ID")
        if not agent_id:
            self.skipTest("Set TEST_AGENT_ID to test fetching a real key")

        key_info = jacs.fetch_remote_key(agent_id, "latest")

        self.assertIsInstance(key_info, PublicKeyInfo)
        self.assertIsInstance(key_info.public_key, bytes)
        self.assertTrue(len(key_info.public_key) > 0)
        self.assertTrue(len(key_info.algorithm) > 0)
        self.assertTrue(len(key_info.public_key_hash) > 0)
        self.assertEqual(key_info.agent_id, agent_id)

    def test_key_not_found_error(self):
        """Test that KeyNotFoundError is raised for non-existent agents."""
        with self.assertRaises(KeyNotFoundError):
            jacs.fetch_remote_key("nonexistent-agent-that-does-not-exist", "latest")


if __name__ == "__main__":
    unittest.main()
