"""FastAPI/Starlette middleware adapter for JACS.

Provides JacsMiddleware (signs responses, verifies requests) and a
@jacs_route decorator for per-endpoint signing.

Usage — middleware (all routes):
    from fastapi import FastAPI
    from jacs.adapters.fastapi import JacsMiddleware

    app = FastAPI()
    app.add_middleware(JacsMiddleware, client=my_client)

Usage — decorator (single route):
    from jacs.adapters.fastapi import jacs_route

    @app.get("/signed")
    @jacs_route(client=my_client)
    def my_endpoint():
        return {"result": "data"}
"""

import json
import logging
from functools import wraps
from typing import Any, Optional

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response
except ImportError as _exc:
    raise ImportError(
        "starlette is required for jacs.adapters.fastapi. "
        "Install it with: pip install jacs[fastapi]"
    ) from _exc

from .base import BaseJacsAdapter

logger = logging.getLogger("jacs.adapters.fastapi")


class JacsMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware that signs responses and verifies requests.

    Args:
        app: The ASGI application.
        client: An existing JacsClient instance. If None, one will be
            created via BaseJacsAdapter's default logic.
        config_path: Path to jacs.config.json (used only if client is None).
        strict: If True, verification failures return 401. If False
            (default), failures are logged and the request passes through.
        sign_responses: If True (default), outgoing JSON responses are signed.
        verify_requests: If True (default), incoming POST bodies with a
            ``jacsSignature`` field are verified.
    """

    def __init__(
        self,
        app: Any,
        client: Any = None,
        config_path: Optional[str] = None,
        strict: bool = False,
        sign_responses: bool = True,
        verify_requests: bool = True,
    ) -> None:
        super().__init__(app)
        self._adapter = BaseJacsAdapter(
            client=client, config_path=config_path, strict=strict
        )
        self.sign_responses = sign_responses
        self.verify_requests = verify_requests

    async def dispatch(self, request: Request, call_next):
        # --- Verify incoming request body ---
        if self.verify_requests and request.method == "POST":
            body = await request.body()
            if body:
                try:
                    data = json.loads(body)
                    if "jacsSignature" in data:
                        if self._adapter.strict:
                            # Strict: raise on failure (will be caught below)
                            self._adapter.verify_input(json.dumps(data))
                        else:
                            self._adapter.verify_input_or_passthrough(
                                json.dumps(data)
                            )
                except json.JSONDecodeError:
                    pass
                except Exception:
                    if self._adapter.strict:
                        return Response(
                            content=json.dumps({"error": "JACS signature verification failed"}),
                            status_code=401,
                            media_type="application/json",
                        )
                    # Permissive mode: already logged by adapter, continue

        response = await call_next(request)

        # --- Sign outgoing JSON responses ---
        if self.sign_responses:
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                body = b""
                async for chunk in response.body_iterator:
                    body += chunk if isinstance(chunk, bytes) else chunk.encode()
                try:
                    data = json.loads(body.decode())
                    signed = self._adapter.sign_output_or_passthrough(data)
                    signed_bytes = (
                        signed.encode() if isinstance(signed, str) else signed
                    )
                    # Build new headers, updating content-length
                    headers = dict(response.headers)
                    headers["content-length"] = str(len(signed_bytes))
                    return Response(
                        content=signed_bytes,
                        status_code=response.status_code,
                        headers=headers,
                        media_type=response.media_type,
                    )
                except Exception:
                    # If signing fails in permissive mode the adapter already
                    # logged; return the original body.
                    return Response(
                        content=body,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        media_type=response.media_type,
                    )

        return response


def jacs_route(
    client: Any = None,
    config_path: Optional[str] = None,
    strict: bool = False,
):
    """Decorator that signs a single FastAPI endpoint's response.

    The decorated function's return value is signed and the signed JACS
    document is returned as a dict (FastAPI will serialize it to JSON).

    Args:
        client: JacsClient instance (or None to auto-create).
        config_path: Path to jacs.config.json.
        strict: Raise on signing failure if True.
    """
    adapter = BaseJacsAdapter(client=client, config_path=config_path, strict=strict)

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            if hasattr(result, "__await__"):
                result = await result
            signed = adapter.sign_output_or_passthrough(result)
            return json.loads(signed)
        return wrapper
    return decorator


__all__ = ["JacsMiddleware", "jacs_route"]
