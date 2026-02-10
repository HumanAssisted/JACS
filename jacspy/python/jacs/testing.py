"""
JACS Test Utilities

Provides a pytest fixture for creating ephemeral JacsClient instances
that are automatically cleaned up after each test.

Usage:
    # In your test file or conftest.py:
    from jacs.testing import jacs_agent

    def test_sign_and_verify(jacs_agent):
        signed = jacs_agent.sign_message({"test": True})
        result = jacs_agent.verify(signed.raw_json)
        assert result.valid
"""

import pytest

from .client import JacsClient


@pytest.fixture
def jacs_agent():
    """Pytest fixture that yields an ephemeral JacsClient.

    The client is created in-memory with no disk I/O or environment
    variables required. It is reset after the test completes.
    """
    client = JacsClient.ephemeral()
    yield client
    client.reset()
