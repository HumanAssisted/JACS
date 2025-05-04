"""
Complete drop‑in enhancement layer for FastMCP that provides

* **JACSFastMCP** – a server wrapper that preserves the familiar
  `@tool`, `@resource`, and `@list` decorators while validating every
  incoming request and automatically signing every response (works for
  stdio, SSE, and WebSocket transports).
* **AuthClient** – a client wrapper that transparently signs outgoing
  requests, validates returned metadata, and works with any FastMCP
  transport. The example below targets SSE.

The file is organised like a miniature package so you can either keep
it as one module or split it into `jacs_mcp/__init__.py`,
`jacs_mcp/fast_mcp_server.py`, and `jacs_mcp/fast_mcp_auth.py`.

Dependencies:  `mcp[cli]`, `fastapi`, `starlette`, `uvicorn`.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import json
import traceback
import uuid
from typing import Any, Awaitable, Callable, Coroutine, Dict, Optional

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response as StarletteResponse, StreamingResponse

# FastMCP primitives
from fastmcp.client.transports import ClientTransport, infer_transport
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import JSONRPCMessage
import jacs

###############################################################################
# Helper callbacks – override if you need different signing/validation rules.
###############################################################################

SyncMetadataCallback = Callable[[Dict[str, Any]], None]


def default_sign_request(params: dict) -> dict:  # CLIENT‑SIDE
    """Attach IDs that the server can validate later."""
    print("default_sign_request: Signing Client Request", params)
    return {"client_id": "c1", "req_id": f"creq-{uuid.uuid4()}"}


def default_validate_request(meta: dict):  # SERVER‑SIDE
    """Fail fast if metadata is missing or malformed."""
    print("default_validate_request: Validating Server Request Metadata", meta)
    if not meta or "client_id" not in meta:
        raise ValueError("metadata.client_id missing")


def default_sign_response(result: Any) -> dict:  # SERVER‑SIDE
    """Add server signature to every success / error payload."""
    print("default_sign_response: Signing Server Response", result)
    return {"server_id": "s1", "res_id": f"sres-{uuid.uuid4()}"}


def default_validate_response(meta: dict):  # CLIENT‑SIDE
    print("default_validate_response: Validating Client Response Metadata", meta)
    if not meta or "server_id" not in meta:
        raise ValueError("metadata.server_id missing")

###############################################################################
# CLIENT – transport wrapper + convenience client
###############################################################################

class _AuthInjectTransport(ClientTransport):
    """Wrap *any* ClientTransport to inject metadata into outgoing calls."""

    def __init__(
        self,
        base_transport: ClientTransport,
        sign_request_fn: Callable[[dict], dict] = default_sign_request,
    ) -> None:
        self._base = base_transport
        self._sign_request = sign_request_fn

    @contextlib.asynccontextmanager
    async def connect_session(self, **kwargs):  # type: ignore[override]
        async with self._base.connect_session(**kwargs) as session:
            original_send = session._write_stream.send  # pylint: disable=protected-access

            async def patched_send(message: JSONRPCMessage, **send_kwargs):  # type: ignore[override]
                if (
                    hasattr(message, "root")
                    and isinstance(message.root, dict)
                    and message.root.get("method")
                ):
                    params: dict | None = message.root.get("params")
                    params = {} if params is None else dict(params)  # shallow‑copy
                    params.setdefault("metadata", {}).update(
                        self._sign_request(params)
                    )
                    message.root["params"] = params
                await original_send(message, **send_kwargs)

            session._write_stream.send = patched_send  # type: ignore[attr-defined]
            try:
                yield session
            finally:
                session._write_stream.send = original_send  # type: ignore[attr-defined]


MessageHandlerFn = Callable[[dict[str, Any]], Coroutine[Any, Any, Optional[dict[str, Any]]]]


def _make_response_validator(
    validate_fn: SyncMetadataCallback,
    downstream: MessageHandlerFn | None = None,
) -> MessageHandlerFn:
    async def handler(message: dict[str, Any]):
        if "metadata" in message:
            validate_fn(message["metadata"])
        if downstream is not None:
            return await downstream(message)
        return message

    return handler


class AuthClient:
    """Drop‑in replacement for `mcp.client.Client` with auto auth & validation."""

    def __init__(
        self,
        transport: str | ClientTransport,
        *,
        sign_request_fn: Callable[[dict], dict] = default_sign_request,
        validate_response_fn: SyncMetadataCallback = default_validate_response,
        **client_kwargs,
    ) -> None:
        base = infer_transport(transport)
        auth_transport = _AuthInjectTransport(base, sign_request_fn)
        message_handler = _make_response_validator(validate_response_fn)
        from fastmcp import Client  # local import to avoid heavy dep when unused

        self._client = Client(auth_transport, message_handler=message_handler, **client_kwargs)

    async def __aenter__(self):
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc):  # noqa: D401
        await self._client.__aexit__(*exc)

    # proxy common methods
    async def call_tool(self, *a, **kw):  # noqa: D401
        return await self._client.call_tool(*a, **kw)

    async def list(self):  # noqa: D401
        return await self._client.list()

###############################################################################
# SERVER – FastMCP wrapper + middleware to sign outgoing payloads
###############################################################################

class _MetadataInjectingMiddleware(BaseHTTPMiddleware):
    """Signs every JSON‑RPC payload leaving the SSE/WS app."""

    def __init__(
        self,
        app: FastAPI,
        *,
        sign_response_fn: Callable[[Any], dict] = default_sign_response,
    ) -> None:
        super().__init__(app)
        self._sign_response = sign_response_fn

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[StarletteResponse]]):  # type: ignore[override]
        response = await call_next(request)

        # Handle SSE streams
        if isinstance(response, StreamingResponse):
            response.body_iterator = self._patch_stream_iter(response.body_iterator)
            return response

        # Handle normal JSON responses
        if response.headers.get("content-type") == "application/json":
            body = b"".join([chunk async for chunk in response.body_iterator])
            response.body_iterator = iter(()).__aiter__()  # empty iterator afterwards
            try:
                data = json.loads(body)
                if isinstance(data, dict) and data.get("jsonrpc") == "2.0":
                    data.setdefault("metadata", {}).update(self._sign_response(data.get("result")))
                    body = json.dumps(data).encode()
            except Exception:  # pragma: no cover
                traceback.print_exc()
            patched = StarletteResponse(content=body, status_code=response.status_code, headers=dict(response.headers), media_type="application/json")
            patched.headers["content-length"] = str(len(body))
            return patched
        return response

    def _patch_stream_iter(self, original_iter):
        async def generator():
            buffer = ""
            async for chunk in original_iter:
                try:
                    buffer += chunk.decode()
                    while "\n\n" in buffer:
                        event, buffer = buffer.split("\n\n", 1)
                        if event.startswith("data:"):
                            raw = json.loads(event[5:].strip())
                            if (
                                isinstance(raw, dict)
                                and raw.get("jsonrpc") == "2.0"
                                and ("result" in raw or "error" in raw)
                            ):
                                raw.setdefault("metadata", {}).update(
                                    self._sign_response(raw.get("result"))
                                )
                                event = f"data: {json.dumps(raw)}"
                        yield (event + "\n\n").encode()
                except Exception:  # pragma: no cover
                    traceback.print_exc()
            if buffer:
                yield buffer.encode()

        return generator()

###############################################################################
# Public server wrapper – mirrors FastMCP API but adds auth.
###############################################################################

class JACSFastMCP:
    """FastMCP with first‑class auth decorators and signed responses."""

    def __init__(
        self,
        name: str,
        *,
        validate_request_fn: SyncMetadataCallback = default_validate_request,
        sign_response_fn: Callable[[Any], dict] = default_sign_response,
        **fastmcp_kwargs,
    ) -> None:
        self._mcp = FastMCP(name, **fastmcp_kwargs)
        self._validate_request = validate_request_fn
        self._sign_response = sign_response_fn

    # ---------------------------------------------------------------------
    # Decorator helpers – tool / resource / list
    # ---------------------------------------------------------------------
    def _wrap_fn(self, fn):
        if getattr(fn, "_jacs_wrapped", False):
            return fn

        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            meta = kwargs.pop("metadata", None)
            self._validate_request(meta)
            sig = inspect.signature(fn)
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            return await fn(*bound.args, **bound.kwargs)

        wrapper._jacs_wrapped = True  # type: ignore[attr-defined]
        return wrapper

    def tool(self, *d_args, **d_kw):  # noqa: D401
        def decorator(fn):
            return self._mcp.tool(*d_args, **d_kw)(self._wrap_fn(fn))

        return decorator

    def resource(self, *d_args, **d_kw):  # noqa: D401
        def decorator(fn):
            return self._mcp.resource(*d_args, **d_kw)(self._wrap_fn(fn))

        return decorator

    def list(self, *d_args, **d_kw):  # noqa: D401 – list handler decorator
        def decorator(fn):
            return self._mcp.list(*d_args, **d_kw)(self._wrap_fn(fn))

        return decorator

    # ------------------------------------------------------------------
    # Transport helpers
    # ------------------------------------------------------------------
    def sse_app(self):
        app = self._mcp.sse_app()
        app.add_middleware(
            _MetadataInjectingMiddleware, sign_response_fn=self._sign_response
        )
        return app

    def ws_app(self):
        app = self._mcp.ws_app()
        app.add_middleware(
            _MetadataInjectingMiddleware, sign_response_fn=self._sign_response
        )
        return app

    def run(self, *a, **kw):  # stdio unchanged
        self._mcp.run(*a, **kw)

    # Convenience proxies
    @property
    def name(self):
        return self._mcp.name

    @property
    def settings(self):
        return self._mcp.settings

###############################################################################
# --------------------------- Example usage ----------------------------------
###############################################################################

if __name__ == "__main__":
    import asyncio
    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import Mount

    # ------------------------------------------------------------------
    # 1. Build a server with auth‑aware decorators
    # ------------------------------------------------------------------
    server = JACSFastMCP("Echo‑Secure")

    @server.tool(description="Echo a message back to the caller")
    async def echo(msg: str) -> str:  # metadata auto‑validated
        return msg

    # Expose over SSE under /sse so it matches the example client
    starlette_app = Starlette(routes=[Mount("/sse", app=server.sse_app())])

    # Run server in background for demo purposes
    async def _launch_server():
        config = uvicorn.Config(starlette_app, host="0.0.0.0", port=8000, log_level="info")
        server_obj = uvicorn.Server(config)
        await server_obj.serve()

    # ------------------------------------------------------------------
    # 2. Example SSE client calling the secured echo tool
    # ------------------------------------------------------------------
    async def _run_client():
        await asyncio.sleep(1)  # give server a moment to start
        from datetime import timedelta

        async with AuthClient(
            "http://localhost:8000/sse",
            read_timeout_seconds=timedelta(seconds=30),  # passes straight through
        ) as client:
            res = await client.call_tool("echo", {"msg": "Hello SSE"})
            print("CLIENT RESULT:", res)

    asyncio.get_event_loop().run_until_complete(
        asyncio.gather(_launch_server(), _run_client())
    )
