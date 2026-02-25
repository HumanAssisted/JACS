"""Tests for the JACS MCP integration wrappers."""

import asyncio
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import json
from types import SimpleNamespace


class TestJACSMCPServerWrapper:
    """Test the JACSMCPServer wrapper function."""

    def test_import_jacs_mcp_server(self):
        """Test that JACSMCPServer can be imported."""
        from jacs.mcp import JACSMCPServer
        assert JACSMCPServer is not None
        assert callable(JACSMCPServer)

    def test_wrapper_returns_modified_server(self):
        """Test that JACSMCPServer returns a modified server object."""
        from jacs.mcp import JACSMCPServer

        # Create a mock FastMCP server
        mock_server = Mock()
        mock_server.sse_app = Mock(return_value=Mock())

        # Wrap it
        wrapped_server = JACSMCPServer(
            mock_server,
            allow_unsigned_fallback=True,
        )

        # The wrapper should return the same object (modified in place)
        assert wrapped_server is mock_server

        # The sse_app should have been replaced
        assert mock_server.sse_app is not None

    def test_wrapper_preserves_server_attributes(self):
        """Test that the wrapper preserves other server attributes."""
        from jacs.mcp import JACSMCPServer

        mock_server = Mock()
        mock_server.sse_app = Mock(return_value=Mock())
        mock_server.some_attribute = "test_value"
        mock_server.some_method = Mock(return_value="method_result")

        wrapped_server = JACSMCPServer(
            mock_server,
            allow_unsigned_fallback=True,
        )

        # Other attributes should be preserved
        assert wrapped_server.some_attribute == "test_value"
        assert wrapped_server.some_method() == "method_result"


class TestJACSMCPClientWrapper:
    """Test the JACSMCPClient wrapper function."""

    def test_import_jacs_mcp_client(self):
        """Test that JACSMCPClient can be imported."""
        from jacs.mcp import JACSMCPClient
        assert JACSMCPClient is not None
        assert callable(JACSMCPClient)


class TestMCPModuleStructure:
    """Test the structure of the MCP module."""

    def test_mcp_module_imports(self):
        """Test that the MCP module can be imported."""
        from jacs import mcp
        assert mcp is not None

    def test_mcp_module_has_expected_exports(self):
        """Test that the MCP module exports expected items."""
        from jacs import mcp

        # Should have the wrapper functions
        assert hasattr(mcp, "JACSMCPServer")
        assert hasattr(mcp, "JACSMCPClient")

    def test_mcp_imports_jacs(self):
        """Test that the MCP module imports the main jacs module."""
        from jacs import mcp

        # The mcp module should use jacs internally
        # We can verify by checking the module source
        import inspect
        source = inspect.getsource(mcp)
        assert "import jacs" in source


class TestMCPSecurityDefaults:
    """Security defaults for MCP wrappers should be hardened."""

    def test_local_only_default_enabled(self):
        from jacs import mcp
        assert mcp._resolve_local_only() is True

    def test_disabling_local_only_is_rejected(self):
        from jacs import mcp
        with pytest.raises(mcp.simple.ConfigError):
            mcp._resolve_local_only(False)

    def test_env_cannot_disable_local_only(self, monkeypatch):
        monkeypatch.setenv("JACS_MCP_LOCAL_ONLY", "false")
        from jacs import mcp
        with pytest.raises(mcp.simple.ConfigError):
            mcp._resolve_local_only()

    def test_unsigned_fallback_default_disabled(self):
        from jacs import mcp
        assert mcp._resolve_allow_unsigned_fallback() is False

    def test_remote_url_rejected_in_local_mode(self):
        from jacs import mcp
        with pytest.raises(mcp.simple.ConfigError):
            mcp._enforce_local_url("https://remote.example.com/sse", "test", True)

    def test_loopback_url_allowed_in_local_mode(self):
        from jacs import mcp
        assert mcp._enforce_local_url("http://127.0.0.1:9000/sse", "test", True) is None

    def test_enforce_local_url_rejects_false_local_only(self):
        from jacs import mcp
        with pytest.raises(mcp.simple.ConfigError):
            mcp._enforce_local_url("http://localhost:9000/sse", "test", False)

    def test_middleware_rejects_remote_client(self):
        from jacs import mcp

        request = SimpleNamespace(
            client=SimpleNamespace(host="203.0.113.9"),
            url=SimpleNamespace(path="/messages/"),
            body=AsyncMock(return_value=b"{}"),
        )
        call_next = AsyncMock()
        middleware = mcp.jacs_middleware()

        if mcp.JSONResponse is None:
            with pytest.raises(mcp.simple.VerificationError):
                asyncio.run(middleware(request, call_next))
            call_next.assert_not_awaited()
        else:
            response = asyncio.run(middleware(request, call_next))
            assert response.status_code == 403
            call_next.assert_not_awaited()

    def test_middleware_allows_loopback_client(self):
        from jacs import mcp

        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            url=SimpleNamespace(path="/messages/"),
            body=AsyncMock(return_value=b"{}"),
        )
        expected_response = SimpleNamespace(headers={"content-type": "text/plain"})
        call_next = AsyncMock(return_value=expected_response)
        middleware = mcp.jacs_middleware()

        response = asyncio.run(middleware(request, call_next))
        assert response is expected_response
        call_next.assert_awaited_once()


class TestMCPMiddlewareBehavior:
    """Test the middleware behavior of the MCP wrappers."""

    def test_server_wrapper_creates_middleware(self):
        """Test that the server wrapper creates authentication middleware."""
        from jacs.mcp import JACSMCPServer

        # Create a mock that behaves like a FastMCP server
        mock_app = Mock()
        mock_app.middleware = Mock(return_value=lambda f: f)

        mock_server = Mock()
        original_sse_app = Mock(return_value=mock_app)
        mock_server.sse_app = original_sse_app

        # Wrap the server
        wrapped = JACSMCPServer(
            mock_server,
            allow_unsigned_fallback=True,
        )

        # Call the patched sse_app to trigger middleware creation
        result_app = wrapped.sse_app()

        # The middleware decorator should have been called
        mock_app.middleware.assert_called_once_with("http")

    def test_server_wrapper_handles_missing_sse_app(self):
        """Test behavior when server doesn't have sse_app."""
        from jacs.mcp import JACSMCPServer

        mock_server = Mock(spec=[])  # Empty spec means no attributes

        with pytest.raises(AttributeError):
            JACSMCPServer(mock_server)


class TestMCPIntegrationTypes:
    """Test type handling in MCP integration."""

    def test_json_serialization_compatibility(self):
        """Test that types used in MCP are JSON serializable."""
        # JACS MCP integration passes data through JSON
        test_payloads = [
            {"jsonrpc": "2.0", "method": "test", "params": {}, "id": 1},
            {"jsonrpc": "2.0", "result": {"data": "value"}, "id": 1},
            {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": 1},
        ]

        for payload in test_payloads:
            # Should be able to serialize and deserialize
            serialized = json.dumps(payload)
            deserialized = json.loads(serialized)
            assert deserialized == payload
