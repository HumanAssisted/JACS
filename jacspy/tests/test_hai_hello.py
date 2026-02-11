"""
Tests for HaiClient.hello_world() and HaiClient.verify_hai_message().

MVP Steps 19-20: Hello world endpoint and HAI message verification.

Uses mock HTTP server since the backend endpoint doesn't exist yet.
"""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

# Skip all tests if jacs module is not available
pytest.importorskip("jacs")

from jacs.hai import (
    HaiClient,
    HelloWorldResult,
    HaiError,
    HaiConnectionError,
    AuthenticationError,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def hai_client():
    """Create a HaiClient instance for testing."""
    return HaiClient(timeout=5.0, max_retries=1)


@pytest.fixture
def mock_agent_loaded():
    """Mock a loaded JACS agent for hello_world tests."""
    mock_info = MagicMock()
    mock_info.agent_id = "test-agent-uuid-1234"

    mock_signed = MagicMock()
    mock_signed.signature = "base64-test-signature"

    with patch("jacs.hai.HaiClient._get_agent_id", return_value="test-agent-uuid-1234"), \
         patch("jacs.hai.HaiClient._get_agent_json", return_value='{"jacsId": "test-agent-uuid-1234"}'), \
         patch("jacs.simple.is_loaded", return_value=True), \
         patch("jacs.simple.sign_message", return_value=mock_signed):
        yield


@pytest.fixture
def mock_hello_response():
    """Standard successful hello response from HAI."""
    return {
        "timestamp": "2026-02-11T22:00:00Z",
        "client_ip": "203.0.113.42",
        "hai_public_key_fingerprint": "sha256:abc123def456",
        "message": "HAI acknowledges your agent",
        "hai_ack_signature": "",
    }


@pytest.fixture
def mock_hello_response_with_signature():
    """Hello response with a HAI signature."""
    return {
        "timestamp": "2026-02-11T22:00:00Z",
        "client_ip": "203.0.113.42",
        "hai_public_key_fingerprint": "sha256:abc123def456",
        "message": "HAI acknowledges your agent",
        "hai_ack_signature": "bW9ja19zaWduYXR1cmU=",
        "hai_public_key": "",
    }


# =============================================================================
# Tests: hello_world()
# =============================================================================


class TestHelloWorld:
    """Tests for HaiClient.hello_world() -- MVP Step 19."""

    def test_hello_world_success(self, hai_client, mock_agent_loaded, mock_hello_response):
        """hello_world() returns HelloWorldResult on 200 response."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_hello_response
        mock_resp.text = json.dumps(mock_hello_response)

        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp
        mock_httpx.ConnectError = Exception
        mock_httpx.TimeoutException = Exception

        hai_client._httpx = mock_httpx

        result = hai_client.hello_world("https://hai.ai")

        assert isinstance(result, HelloWorldResult)
        assert result.success is True
        assert result.timestamp == "2026-02-11T22:00:00Z"
        assert result.client_ip == "203.0.113.42"
        assert result.hai_public_key_fingerprint == "sha256:abc123def456"
        assert result.message == "HAI acknowledges your agent"

    def test_hello_world_sends_jacs_auth_header(self, hai_client, mock_agent_loaded, mock_hello_response):
        """hello_world() sends Authorization: JACS header."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_hello_response
        mock_resp.text = json.dumps(mock_hello_response)

        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp
        mock_httpx.ConnectError = Exception
        mock_httpx.TimeoutException = Exception

        hai_client._httpx = mock_httpx

        hai_client.hello_world("https://hai.ai")

        # Verify the POST was called
        mock_httpx.post.assert_called_once()
        call_kwargs = mock_httpx.post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})

        # Authorization header should use JACS scheme
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("JACS ")
        # Format: JACS {agentId}:{timestamp}:{signature}
        parts = headers["Authorization"][len("JACS "):].split(":")
        assert len(parts) >= 3
        assert parts[0] == "test-agent-uuid-1234"

    def test_hello_world_correct_url(self, hai_client, mock_agent_loaded, mock_hello_response):
        """hello_world() POSTs to /api/v1/agents/hello."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_hello_response
        mock_resp.text = json.dumps(mock_hello_response)

        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp
        mock_httpx.ConnectError = Exception
        mock_httpx.TimeoutException = Exception

        hai_client._httpx = mock_httpx

        hai_client.hello_world("https://hai.ai")

        call_args = mock_httpx.post.call_args
        url = call_args[0][0] if call_args[0] else call_args.kwargs.get("url", "")
        assert url == "https://hai.ai/api/v1/agents/hello"

    def test_hello_world_include_test(self, hai_client, mock_agent_loaded, mock_hello_response):
        """hello_world(include_test=True) sends include_test in payload."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_hello_response
        mock_resp.text = json.dumps(mock_hello_response)

        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp
        mock_httpx.ConnectError = Exception
        mock_httpx.TimeoutException = Exception

        hai_client._httpx = mock_httpx

        hai_client.hello_world("https://hai.ai", include_test=True)

        call_kwargs = mock_httpx.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json", {})
        assert payload.get("include_test") is True

    def test_hello_world_401_raises_auth_error(self, hai_client, mock_agent_loaded):
        """hello_world() raises AuthenticationError on 401."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {"error": "Invalid JACS signature"}
        mock_resp.text = '{"error": "Invalid JACS signature"}'

        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp
        mock_httpx.ConnectError = Exception
        mock_httpx.TimeoutException = Exception

        hai_client._httpx = mock_httpx

        with pytest.raises(AuthenticationError) as exc_info:
            hai_client.hello_world("https://hai.ai")

        assert exc_info.value.status_code == 401

    def test_hello_world_429_raises_rate_limit(self, hai_client, mock_agent_loaded):
        """hello_world() raises HaiError on 429 rate limit."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = ""

        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp
        mock_httpx.ConnectError = Exception
        mock_httpx.TimeoutException = Exception

        hai_client._httpx = mock_httpx

        with pytest.raises(HaiError) as exc_info:
            hai_client.hello_world("https://hai.ai")

        assert "Rate limited" in str(exc_info.value)

    def test_hello_world_connection_error(self, hai_client, mock_agent_loaded):
        """hello_world() raises HaiConnectionError on network failure."""
        mock_httpx = MagicMock()
        # Create a real exception class hierarchy for httpx errors
        connect_error_cls = type("ConnectError", (Exception,), {})
        timeout_error_cls = type("TimeoutException", (Exception,), {})
        mock_httpx.ConnectError = connect_error_cls
        mock_httpx.TimeoutException = timeout_error_cls
        mock_httpx.post.side_effect = connect_error_cls("Connection refused")

        hai_client._httpx = mock_httpx

        with pytest.raises(HaiConnectionError):
            hai_client.hello_world("https://hai.ai")

    def test_hello_world_no_agent_loaded(self, hai_client):
        """hello_world() raises HaiError when no agent is loaded."""
        with patch("jacs.hai.HaiClient._get_agent_id", side_effect=Exception("No agent")):
            with pytest.raises(HaiError):
                hai_client.hello_world("https://hai.ai")

    def test_hello_world_result_dataclass(self):
        """HelloWorldResult has correct fields and defaults."""
        result = HelloWorldResult(success=True)
        assert result.success is True
        assert result.timestamp == ""
        assert result.client_ip == ""
        assert result.hai_public_key_fingerprint == ""
        assert result.message == ""
        assert result.hai_signature_valid is False
        assert result.raw_response == {}

    def test_hello_world_preserves_raw_response(self, hai_client, mock_agent_loaded):
        """hello_world() preserves the full raw response."""
        response_data = {
            "timestamp": "2026-02-11T22:00:00Z",
            "client_ip": "10.0.0.1",
            "hai_public_key_fingerprint": "sha256:xyz",
            "message": "HAI acknowledges your agent",
            "hai_ack_signature": "",
            "extra_field": "preserved",
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response_data
        mock_resp.text = json.dumps(response_data)

        mock_httpx = MagicMock()
        mock_httpx.post.return_value = mock_resp
        mock_httpx.ConnectError = Exception
        mock_httpx.TimeoutException = Exception

        hai_client._httpx = mock_httpx

        result = hai_client.hello_world("https://hai.ai")
        assert result.raw_response["extra_field"] == "preserved"


# =============================================================================
# Tests: verify_hai_message()
# =============================================================================


class TestVerifyHaiMessage:
    """Tests for HaiClient.verify_hai_message() -- MVP Step 20."""

    def test_verify_empty_signature_returns_false(self, hai_client):
        """verify_hai_message() returns False for empty signature."""
        assert hai_client.verify_hai_message(
            message="hello",
            signature="",
        ) is False

    def test_verify_empty_message_returns_false(self, hai_client):
        """verify_hai_message() returns False for empty message."""
        assert hai_client.verify_hai_message(
            message="",
            signature="base64sig",
        ) is False

    def test_verify_jacs_signed_document(self, hai_client):
        """verify_hai_message() delegates to jacs.simple.verify for JACS documents."""
        jacs_doc = json.dumps({
            "jacsId": "doc-123",
            "jacsSignature": {
                "agentId": "agent-456",
                "signature": "sig-data",
                "date": "2026-01-01T00:00:00Z",
            },
            "content": "test",
        })

        mock_result = MagicMock()
        mock_result.valid = True

        with patch("jacs.simple.verify", return_value=mock_result):
            result = hai_client.verify_hai_message(
                message=jacs_doc,
                signature="unused-for-jacs-docs",
            )
            assert result is True

    def test_verify_jacs_signed_document_invalid(self, hai_client):
        """verify_hai_message() returns False for invalid JACS documents."""
        jacs_doc = json.dumps({
            "jacsId": "doc-123",
            "jacsSignature": {
                "agentId": "agent-456",
                "signature": "bad-sig",
            },
            "content": "tampered",
        })

        mock_result = MagicMock()
        mock_result.valid = False

        with patch("jacs.simple.verify", return_value=mock_result):
            result = hai_client.verify_hai_message(
                message=jacs_doc,
                signature="unused",
            )
            assert result is False

    def test_verify_without_public_key_returns_false(self, hai_client):
        """verify_hai_message() returns False for raw messages without public key."""
        result = hai_client.verify_hai_message(
            message='{"status": "ok"}',
            signature="bW9ja19zaWduYXR1cmU=",
            hai_public_key="",
        )
        assert result is False

    def test_verify_non_json_message_without_key_returns_false(self, hai_client):
        """verify_hai_message() returns False for plain text without key."""
        result = hai_client.verify_hai_message(
            message="plain text message",
            signature="bW9ja19zaWduYXR1cmU=",
        )
        assert result is False


# =============================================================================
# Tests: Module-level hello_world() convenience function
# =============================================================================


class TestModuleLevelHelloWorld:
    """Tests for module-level hello_world() function."""

    def test_module_function_delegates_to_client(self):
        """Module-level hello_world() delegates to HaiClient."""
        from jacs import hai

        mock_result = HelloWorldResult(
            success=True,
            message="HAI acknowledges your agent",
        )

        with patch.object(HaiClient, "hello_world", return_value=mock_result) as mock_method:
            result = hai.hello_world("https://hai.ai")
            assert result.success is True
            mock_method.assert_called_once_with("https://hai.ai", False)

    def test_module_function_passes_include_test(self):
        """Module-level hello_world() passes include_test parameter."""
        from jacs import hai

        mock_result = HelloWorldResult(success=True)

        with patch.object(HaiClient, "hello_world", return_value=mock_result) as mock_method:
            hai.hello_world("https://hai.ai", include_test=True)
            mock_method.assert_called_once_with("https://hai.ai", True)


# =============================================================================
# Tests: HelloWorldResult in __all__
# =============================================================================


class TestExports:
    """Test that new types are properly exported."""

    def test_hello_world_result_in_all(self):
        """HelloWorldResult is in __all__."""
        from jacs.hai import __all__
        assert "HelloWorldResult" in __all__

    def test_hello_world_function_in_all(self):
        """hello_world function is in __all__."""
        from jacs.hai import __all__
        assert "hello_world" in __all__

    def test_can_import_hello_world_result(self):
        """HelloWorldResult is importable from jacs.hai."""
        from jacs.hai import HelloWorldResult
        assert HelloWorldResult is not None

    def test_can_import_hello_world_function(self):
        """hello_world function is importable from jacs.hai."""
        from jacs.hai import hello_world
        assert callable(hello_world)
