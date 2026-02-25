"""JACS MCP (Model Context Protocol) Integration.

Provides both class-based and simplified wrappers for adding JACS
cryptographic signing and verification to MCP transports and servers.

Quick start (simple API):
    from jacs.mcp import create_jacs_mcp_server
    mcp = create_jacs_mcp_server("My Server", "./jacs.config.json")
    mcp.run()

Class-based client:
    from jacs.mcp import JACSMCPClient
    client = JACSMCPClient("http://localhost:8000/sse", "jacs.config.json")
    async with client.connect() as session:
        result = await session.call_tool("my_tool", {"arg": "value"})

Class-based server:
    from jacs.mcp import JACSMCPServer
    from fastmcp import FastMCP
    mcp = FastMCP("My Server")
    mcp = JACSMCPServer(mcp, "jacs.config.json")

Requires (optional): fastmcp, mcp, starlette
"""

import contextlib
import ipaddress
import json
import logging
import os
from typing import Any, Callable, Dict, Optional
from functools import wraps
from urllib.parse import urlparse

from . import simple


def _resolve_strict(strict: Optional[bool] = None) -> bool:
    """Return True if strict mode is active (parameter or env var)."""
    if strict is not None:
        return strict
    return os.environ.get("JACS_STRICT_MODE", "").lower() in ("1", "true")


def _resolve_local_only(local_only: Optional[bool] = None) -> bool:
    """Return True for MCP local-only mode; disabling is not allowed."""
    raw = os.environ.get("JACS_MCP_LOCAL_ONLY", "").strip().lower()
    env_disable = raw in ("0", "false", "no")
    if local_only is False or env_disable:
        raise simple.ConfigError(
            "JACS MCP local mode only: disabling local-only mode is not allowed."
        )
    return True


def _resolve_allow_unsigned_fallback(
    allow_unsigned_fallback: Optional[bool] = None,
) -> bool:
    """Return True if unsigned fallback is explicitly allowed (default: False)."""
    if allow_unsigned_fallback is not None:
        return allow_unsigned_fallback
    raw = os.environ.get("JACS_MCP_ALLOW_UNSIGNED_FALLBACK", "").strip().lower()
    return raw in ("1", "true", "yes")


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower().strip("[]")
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_loopback_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.hostname:
        return False
    return _is_loopback_host(parsed.hostname)


def _enforce_local_url(url: str, context: str, local_only: bool) -> None:
    if not local_only:
        raise simple.ConfigError(
            "JACS MCP local mode only: disabling local-only mode is not allowed."
        )
    if not _is_loopback_url(url):
        raise simple.ConfigError(
            f"{context}: local mode only. URL must use localhost/127.0.0.1/::1. "
            "Remote MCP URLs are not allowed."
        )

try:
    import jacs
    from jacs import JacsAgent
except ImportError:
    JacsAgent = None  # type: ignore[assignment, misc]

try:
    from fastmcp import Client
    from fastmcp.client.transports import SSETransport
except ImportError:
    Client = None  # type: ignore[assignment, misc]
    SSETransport = None  # type: ignore[assignment, misc]

try:
    from mcp.client.sse import sse_client
    from mcp import ClientSession
except ImportError:
    sse_client = None  # type: ignore[assignment]
    ClientSession = None  # type: ignore[assignment, misc]

try:
    from starlette.responses import Response, JSONResponse
except ImportError:
    Response = None  # type: ignore[assignment, misc]
    JSONResponse = None  # type: ignore[assignment, misc]


LOGGER = logging.getLogger("jacs.mcp")


# ---------------------------------------------------------------------------
# Class-based API (uses JacsAgent instances)
# ---------------------------------------------------------------------------


def JACSMCPClient(
    url,
    config_path="./jacs.config.json",
    strict=False,
    local_only: Optional[bool] = None,
    allow_unsigned_fallback: Optional[bool] = None,
    **kwargs,
):
    """Creates a FastMCP client with JACS signing/verification interceptors.

    Args:
        url: The SSE endpoint URL
        config_path: Path to jacs.config.json
        strict: If True, config failures raise instead of falling back to
            unsigned transport. Also enabled by JACS_STRICT_MODE env var.
        local_only: Reserved for compatibility. Local-only is always enforced.
        allow_unsigned_fallback: If True, signing/verification failures
            can pass through unsigned messages (default: False).
        **kwargs: Additional arguments passed to FastMCP Client
    """
    if Client is None or SSETransport is None:
        raise ImportError(
            "fastmcp is required for JACSMCPClient. Install with: pip install fastmcp"
        )
    if JacsAgent is None:
        raise ImportError("jacs native module is required for JACSMCPClient")

    strict = _resolve_strict(strict)
    local_only = _resolve_local_only(local_only)
    allow_unsigned_fallback = _resolve_allow_unsigned_fallback(allow_unsigned_fallback)
    _enforce_local_url(url, "JACSMCPClient", local_only)
    agent = JacsAgent()
    agent_ready = True
    try:
        agent.load(config_path)
    except Exception as e:
        if strict or not allow_unsigned_fallback:
            raise simple.ConfigError(
                f"JACS secure mode: refusing to run unsigned. "
                f"Fix config at '{config_path}' or set "
                f"JACS_MCP_ALLOW_UNSIGNED_FALLBACK=true to allow unsigned "
                f"transport. Error: {e}"
            ) from e
        LOGGER.warning(
            "Failed to load JACS config '%s' for MCP client; transport will run unsigned: %s",
            config_path,
            e,
        )
        agent_ready = False

    transport = SSETransport(url)

    @contextlib.asynccontextmanager
    async def patched_connect_session(**session_kwargs):
        async with sse_client(transport.url, headers=transport.headers) as transport_streams:
            original_read_stream, original_write_stream = transport_streams

            original_send = original_write_stream.send
            async def intercepted_send(message, **send_kwargs):
                if agent_ready and isinstance(message.root, dict):
                    try:
                        signed_json = agent.sign_request(message.root)
                        message.root = json.loads(signed_json)
                    except Exception as e:
                        if not allow_unsigned_fallback:
                            raise simple.SigningError(
                                f"JACS signing failed and unsigned fallback is disabled: {e}"
                            ) from e
                        LOGGER.warning("JACS signing failed, falling back to unsigned message: %s", e)
                return await original_send(message, **send_kwargs)

            original_write_stream.send = intercepted_send

            original_receive = original_read_stream.receive
            async def intercepted_receive(**receive_kwargs):
                message = await original_receive(**receive_kwargs)
                if agent_ready and isinstance(message.root, dict):
                    try:
                        payload = agent.verify_response(json.dumps(message.root))
                        message.root = payload
                    except Exception as e:
                        if not allow_unsigned_fallback:
                            raise simple.VerificationError(
                                "JACS verification failed and unsigned fallback is disabled: "
                                f"{e}"
                            ) from e
                        LOGGER.warning(
                            "JACS verification failed, falling back to unsigned message: %s",
                            e,
                        )
                return message

            original_read_stream.receive = intercepted_receive

            async with ClientSession(
                original_read_stream, original_write_stream, **session_kwargs
            ) as session:
                await session.initialize()
                yield session

    transport.connect_session = patched_connect_session
    return Client(transport, **kwargs)


def JACSMCPServer(
    mcp_server,
    config_path="./jacs.config.json",
    strict=False,
    local_only: Optional[bool] = None,
    allow_unsigned_fallback: Optional[bool] = None,
):
    """Creates a FastMCP server with JACS signing/verification interceptors.

    Args:
        mcp_server: A FastMCP server instance
        config_path: Path to jacs.config.json
        strict: If True, config failures raise instead of falling back to
            unsigned passthrough. Also enabled by JACS_STRICT_MODE env var.
        local_only: Reserved for compatibility. Local-only is always enforced.
        allow_unsigned_fallback: If True, verification/signing failures
            can pass through unsigned messages (default: False).
    """
    if not hasattr(mcp_server, "sse_app"):
        raise AttributeError("mcp_server is missing required attribute 'sse_app'")

    if JacsAgent is None:
        raise ImportError("jacs native module is required for JACSMCPServer")

    strict = _resolve_strict(strict)
    local_only = _resolve_local_only(local_only)
    allow_unsigned_fallback = _resolve_allow_unsigned_fallback(allow_unsigned_fallback)
    agent = JacsAgent()
    agent_ready = True
    try:
        agent.load(config_path)
    except Exception as e:
        if strict or not allow_unsigned_fallback:
            raise simple.ConfigError(
                f"JACS secure mode: refusing to run unsigned. "
                f"Fix config at '{config_path}' or set "
                f"JACS_MCP_ALLOW_UNSIGNED_FALLBACK=true to allow unsigned "
                f"passthrough. Error: {e}"
            ) from e
        LOGGER.warning(
            "Failed to load JACS config '%s' for MCP server; middleware will pass through unsigned: %s",
            config_path,
            e,
        )
        agent_ready = False

    original_sse_app = mcp_server.sse_app

    def patched_sse_app():
        app = original_sse_app()

        @app.middleware("http")
        async def jacs_authentication_middleware(request, call_next):
            request_host = getattr(getattr(request, "client", None), "host", "") or ""
            if local_only and not _is_loopback_host(request_host):
                if JSONResponse is not None:
                    return JSONResponse(
                        {"error": "MCP local mode only: remote clients are not allowed"},
                        status_code=403,
                    )
                raise simple.VerificationError(
                    "MCP local mode only: remote clients are not allowed"
                )

            if request.url.path.endswith("/messages/"):
                body = await request.body()
                if agent_ready and body:
                    try:
                        data = json.loads(body)
                        payload = agent.verify_response(json.dumps(data))
                        request._body = json.dumps(payload).encode()
                    except Exception as e:
                        if allow_unsigned_fallback:
                            LOGGER.warning("JACS verification failed: %s", e)
                        elif JSONResponse is not None:
                            return JSONResponse(
                                {"error": f"JACS verification failed: {e}"},
                                status_code=401,
                            )
                        else:
                            raise

            response = await call_next(request)

            if "application/json" in response.headers.get("content-type", ""):
                body = b""
                async for chunk in response.body_iterator:
                    body += chunk

                if agent_ready:
                    try:
                        data = json.loads(body.decode())
                        signed_json = agent.sign_request(data)
                        return Response(
                            content=signed_json.encode(),
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            media_type=response.media_type,
                        )
                    except Exception as e:
                        if allow_unsigned_fallback:
                            LOGGER.warning("JACS signing failed: %s", e)
                        elif JSONResponse is not None:
                            return JSONResponse(
                                {"error": f"JACS signing failed: {e}"},
                                status_code=500,
                            )
                        else:
                            raise

            return response

        return app

    mcp_server.sse_app = patched_sse_app
    return mcp_server


# ---------------------------------------------------------------------------
# Simple API (uses module-level simple.* globals)
# ---------------------------------------------------------------------------


def sign_mcp_message(message: Dict[str, Any]) -> str:
    """Sign an MCP message and return signed JSON string.

    Args:
        message: The MCP message dict (JSON-RPC format)

    Returns:
        Signed JACS document as JSON string

    Example:
        signed = sign_mcp_message({"jsonrpc": "2.0", "method": "hello"})
    """
    if not simple.is_loaded():
        raise simple.AgentNotLoadedError(
            "No agent loaded. Call jacs.load() first."
        )

    signed = simple.sign_message(json.dumps(message))
    return signed.raw_json


def verify_mcp_message(signed_json: str) -> Dict[str, Any]:
    """Verify a signed MCP message and return the payload.

    Args:
        signed_json: Signed JACS document as JSON string

    Returns:
        The original MCP message dict

    Raises:
        VerificationError: If signature verification fails

    Example:
        message = verify_mcp_message(signed_json)
        print(message["method"])
    """
    if not simple.is_loaded():
        raise simple.AgentNotLoadedError(
            "No agent loaded. Call jacs.load() first."
        )

    result = simple.verify(signed_json)

    if not result.valid:
        raise simple.VerificationError(
            f"MCP message verification failed: {result.error}"
        )

    doc = json.loads(signed_json)
    payload = doc.get("jacsDocument", {})

    if isinstance(payload.get("content"), str):
        try:
            return json.loads(payload["content"])
        except json.JSONDecodeError:
            return payload

    return payload


def jacs_tool(func: Callable) -> Callable:
    """Decorator to add JACS signing to an MCP tool.

    Use this decorator on MCP tool functions to automatically
    sign the response.

    Example:
        @mcp.tool()
        @jacs_tool
        def my_tool(arg: str) -> str:
            return f"Result: {arg}"
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)

        if hasattr(result, '__await__'):
            result = await result

        if simple.is_loaded():
            signed = simple.sign_message(json.dumps(result))
            return json.loads(signed.raw_json)

        return result

    return wrapper


def jacs_middleware(
    *,
    local_only: Optional[bool] = None,
    allow_unsigned_fallback: Optional[bool] = None,
):
    """Create Starlette HTTP middleware for JACS authentication.

    Returns middleware that can be added to FastMCP servers via
    ``app.middleware("http")`` to automatically sign all JSON responses
    and verify incoming requests that carry a JACS signature.
    Defaults to local-only + fail-closed behavior.

    Uses the simplified ``simple.*`` module API (module-level globals).

    Example:
        from starlette.applications import Starlette
        app = Starlette()

        @app.middleware("http")
        async def mw(request, call_next):
            return await jacs_middleware()(request, call_next)
    """
    local_only = _resolve_local_only(local_only)
    allow_unsigned_fallback = _resolve_allow_unsigned_fallback(allow_unsigned_fallback)

    async def middleware(request, call_next):
        request_host = getattr(getattr(request, "client", None), "host", "") or ""
        if local_only and not _is_loopback_host(request_host):
            if JSONResponse is not None:
                return JSONResponse(
                    {"error": "MCP local mode only: remote clients are not allowed"},
                    status_code=403,
                )
            raise simple.VerificationError(
                "MCP local mode only: remote clients are not allowed"
            )

        # Verify incoming request if it has a JACS signature
        body = await request.body()
        if body:
            try:
                data = json.loads(body)
                if "jacsSignature" in data:
                    result = simple.verify(body.decode())
                    if not result.valid:
                        if JSONResponse is not None:
                            return JSONResponse(
                                {"error": f"JACS verification failed: {result.error}"},
                                status_code=401,
                            )
            except json.JSONDecodeError:
                pass
            except Exception as e:
                if allow_unsigned_fallback:
                    LOGGER.warning("JACS verification failed: %s", e)
                elif JSONResponse is not None:
                    return JSONResponse(
                        {"error": f"JACS verification failed: {e}"},
                        status_code=401,
                    )
                else:
                    raise

        response = await call_next(request)

        # Sign outgoing JSON responses
        if simple.is_loaded() and Response is not None:
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                resp_body = b""
                async for chunk in response.body_iterator:
                    resp_body += chunk

                try:
                    data = json.loads(resp_body.decode())
                    signed = simple.sign_message(json.dumps(data))
                    return Response(
                        content=signed.raw_json.encode(),
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        media_type=response.media_type,
                    )
                except Exception as e:
                    if allow_unsigned_fallback:
                        LOGGER.warning("JACS response signing failed: %s", e)
                    elif JSONResponse is not None:
                        return JSONResponse(
                            {"error": f"JACS response signing failed: {e}"},
                            status_code=500,
                        )
                    else:
                        raise

        return response

    return middleware


class JacsSSETransport:
    """SSE transport wrapper with JACS signing/verification.

    Wraps fastmcp's ``SSETransport`` and intercepts ``send``/``receive``
    to transparently sign outgoing messages and verify incoming ones,
    using the simplified ``simple.*`` module API.

    Example:
        import jacs.simple as jacs
        from jacs.mcp import JacsSSETransport
        from fastmcp import Client

        jacs.load("./jacs.config.json")
        transport = JacsSSETransport("http://localhost:8000/sse")
        client = Client(transport)
        async with client:
            result = await client.call_tool("hello", {"name": "World"})
    """

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        *,
        local_only: Optional[bool] = None,
        allow_unsigned_fallback: Optional[bool] = None,
    ):
        if SSETransport is None:
            raise ImportError(
                "fastmcp is required for JacsSSETransport. "
                "Install with: pip install fastmcp"
            )
        local_only = _resolve_local_only(local_only)
        _enforce_local_url(url, "JacsSSETransport", local_only)
        self._allow_unsigned_fallback = _resolve_allow_unsigned_fallback(
            allow_unsigned_fallback
        )
        self._inner = SSETransport(url, headers=headers)

    # Proxy attributes so fastmcp.Client can use this as a transport
    @property
    def url(self):
        return self._inner.url

    @property
    def headers(self):
        return self._inner.headers

    @contextlib.asynccontextmanager
    async def connect_session(self, **session_kwargs):
        """Connect with JACS signing/verification interceptors."""
        if sse_client is None or ClientSession is None:
            raise ImportError(
                "mcp is required for JacsSSETransport. "
                "Install with: pip install mcp"
            )

        agent_ready = simple.is_loaded()

        async with sse_client(self._inner.url, headers=self._inner.headers) as transport_streams:
            original_read_stream, original_write_stream = transport_streams

            original_send = original_write_stream.send
            async def intercepted_send(message, **send_kwargs):
                if agent_ready and isinstance(message.root, dict):
                    signed = sign_mcp_message(message.root)
                    message.root = json.loads(signed)
                return await original_send(message, **send_kwargs)

            original_write_stream.send = intercepted_send

            original_receive = original_read_stream.receive
            async def intercepted_receive(**receive_kwargs):
                message = await original_receive(**receive_kwargs)
                if agent_ready and isinstance(message.root, dict):
                    try:
                        payload = verify_mcp_message(json.dumps(message.root))
                        message.root = payload
                    except Exception as e:
                        if self._allow_unsigned_fallback:
                            LOGGER.warning("JACS verification on receive failed: %s", e)
                        else:
                            raise simple.VerificationError(
                                "JACS verification failed and unsigned fallback is disabled: "
                                f"{e}"
                            ) from e
                return message

            original_read_stream.receive = intercepted_receive

            async with ClientSession(
                original_read_stream, original_write_stream, **session_kwargs
            ) as session:
                await session.initialize()
                yield session


def create_jacs_mcp_server(
    name: str,
    config_path: Optional[str] = None,
    *,
    local_only: Optional[bool] = None,
    allow_unsigned_fallback: Optional[bool] = None,
):
    """Create a FastMCP server with JACS authentication built-in.

    This is the simplest way to create an authenticated MCP server.
    It loads the JACS agent from ``config_path``, creates a FastMCP
    server, and wires up ``jacs_middleware()`` so every JSON response
    is signed and every signed request is verified automatically.

    Args:
        name: Server name
        config_path: Path to JACS config (default: ./jacs.config.json)

    Returns:
        Configured FastMCP server instance

    Example:
        mcp = create_jacs_mcp_server("My Server")

        @mcp.tool()
        def hello(name: str) -> str:
            return f"Hello, {name}!"

        mcp.run()
    """
    try:
        from fastmcp import FastMCP
    except ImportError:
        raise ImportError(
            "fastmcp is required for MCP server support. "
            "Install with: pip install fastmcp"
        )

    # Load JACS agent via the simple module-level API
    simple.load(config_path)

    # Create FastMCP server
    mcp_server = FastMCP(name)

    # Wire JACS middleware into the SSE app
    original_sse_app = mcp_server.sse_app
    middleware_fn = jacs_middleware(
        local_only=local_only,
        allow_unsigned_fallback=allow_unsigned_fallback,
    )

    def patched_sse_app():
        app = original_sse_app()

        @app.middleware("http")
        async def _jacs_mw(request, call_next):
            return await middleware_fn(request, call_next)

        return app

    mcp_server.sse_app = patched_sse_app
    return mcp_server


async def jacs_call(
    server_url: str,
    method: str,
    local_only: Optional[bool] = None,
    **params: Any,
) -> Any:
    """Make an authenticated MCP call to a server.

    This is a convenience function for making one-off MCP calls
    with JACS authentication.

    Args:
        server_url: URL of the MCP server
        method: MCP method to call
        local_only: Reserved for compatibility. Local-only is always enforced.
        **params: Parameters for the method

    Returns:
        The method result

    Example:
        result = await jacs_call(
            "http://localhost:8000",
            "hello",
            name="World"
        )
    """
    if not simple.is_loaded():
        raise simple.AgentNotLoadedError(
            "No agent loaded. Call jacs.load() first."
        )

    if Client is None or SSETransport is None:
        raise ImportError(
            "fastmcp is required for MCP client support. "
            "Install with: pip install fastmcp"
        )

    local_only = _resolve_local_only(local_only)
    _enforce_local_url(server_url, "jacs_call", local_only)

    transport = SSETransport(server_url)
    client = Client(transport)

    async with client:
        result = await client.call_tool(method, params)
        return result


__all__ = [
    # Class-based API
    "JACSMCPClient",
    "JACSMCPServer",
    # Simple API
    "sign_mcp_message",
    "verify_mcp_message",
    "jacs_tool",
    "jacs_middleware",
    "JacsSSETransport",
    "create_jacs_mcp_server",
    "jacs_call",
]
