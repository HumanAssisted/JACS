"""JACS MCP (Model Context Protocol) Transport Interceptors.

Provides client and server wrappers that add JACS signing and verification
to MCP transports. Messages are signed on send and verified on receive.

Requires: fastmcp, mcp, starlette

Example (Client):
    from jacs.mcp import JACSMCPClient
    client = JACSMCPClient("http://localhost:8000/sse", "jacs.config.json")
    async with client.connect() as session:
        result = await session.call_tool("my_tool", {"arg": "value"})

Example (Server):
    from jacs.mcp import JACSMCPServer
    from fastmcp import FastMCP
    mcp = FastMCP("My Server")
    mcp = JACSMCPServer(mcp, "jacs.config.json")
"""

import contextlib
import json
import logging

import jacs
from jacs import JacsAgent

from fastmcp import Client
from fastmcp.client.transports import SSETransport
from mcp.client.sse import sse_client
from mcp import ClientSession
from starlette.responses import Response

LOGGER = logging.getLogger("jacs.mcp")


def JACSMCPClient(url, config_path="./jacs.config.json", **kwargs):
    """Creates a FastMCP client with JACS signing/verification interceptors.

    Args:
        url: The SSE endpoint URL
        config_path: Path to jacs.config.json
        **kwargs: Additional arguments passed to FastMCP Client
    """
    agent = JacsAgent()
    agent_ready = True
    try:
        agent.load(config_path)
    except Exception as e:
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
                    signed_json = agent.sign_request(message.root)
                    message.root = json.loads(signed_json)
                return await original_send(message, **send_kwargs)

            original_write_stream.send = intercepted_send

            original_receive = original_read_stream.receive
            async def intercepted_receive(**receive_kwargs):
                message = await original_receive(**receive_kwargs)
                if agent_ready and isinstance(message.root, dict):
                    payload = agent.verify_response(json.dumps(message.root))
                    message.root = payload
                return message

            original_read_stream.receive = intercepted_receive

            async with ClientSession(
                original_read_stream, original_write_stream, **session_kwargs
            ) as session:
                await session.initialize()
                yield session

    transport.connect_session = patched_connect_session
    return Client(transport, **kwargs)


def JACSMCPServer(mcp_server, config_path="./jacs.config.json"):
    """Creates a FastMCP server with JACS signing/verification interceptors.

    Args:
        mcp_server: A FastMCP server instance
        config_path: Path to jacs.config.json
    """
    if not hasattr(mcp_server, "sse_app"):
        raise AttributeError("mcp_server is missing required attribute 'sse_app'")

    agent = JacsAgent()
    agent_ready = True
    try:
        agent.load(config_path)
    except Exception as e:
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
            if request.url.path.endswith("/messages/"):
                body = await request.body()
                if agent_ready and body:
                    try:
                        data = json.loads(body)
                        payload = agent.verify_response(json.dumps(data))
                        request._body = json.dumps(payload).encode()
                    except Exception as e:
                        LOGGER.warning("JACS verification failed: %s", e)

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
                        LOGGER.warning("JACS signing failed: %s", e)

            return response

        return app

    mcp_server.sse_app = patched_sse_app
    return mcp_server
