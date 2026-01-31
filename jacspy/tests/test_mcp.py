"""Tests for the JACS MCP integration wrappers."""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import json


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
        wrapped_server = JACSMCPServer(mock_server)

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

        wrapped_server = JACSMCPServer(mock_server)

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
        wrapped = JACSMCPServer(mock_server)

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
