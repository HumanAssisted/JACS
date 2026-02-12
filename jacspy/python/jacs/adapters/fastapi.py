"""FastAPI/Starlette middleware adapter for JACS.

Provides JacsMiddleware (signs responses, verifies requests) and a
@jacs_route decorator for per-endpoint signing.

Usage — middleware (all routes):
    from fastapi import FastAPI
    from jacs.adapters.fastapi import JacsMiddleware

    app = FastAPI()
    app.add_middleware(JacsMiddleware, client=my_client)

Usage — middleware with A2A discovery routes:
    app.add_middleware(JacsMiddleware, client=my_client, a2a=True)
    # Now serves /.well-known/agent-card.json and friends

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
from typing import Any, List, Dict, Optional

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
        a2a: If True, serve A2A well-known discovery documents.
            The middleware intercepts requests to ``/.well-known/*``
            and responds directly.  Requires a ``client`` with a loaded
            agent.  Documents are cached at startup (not regenerated
            per request).
        a2a_skills: Optional list of JACS service dicts to override
            the agent's own services in the exported Agent Card.
    """

    def __init__(
        self,
        app: Any,
        client: Any = None,
        config_path: Optional[str] = None,
        strict: bool = False,
        sign_responses: bool = True,
        verify_requests: bool = True,
        a2a: bool = False,
        a2a_skills: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self._adapter = BaseJacsAdapter(
            client=client, config_path=config_path, strict=strict
        )
        self.sign_responses = sign_responses
        self.verify_requests = verify_requests
        self._a2a_docs: Optional[Dict[str, Any]] = None

        if a2a:
            self._build_a2a_docs(a2a_skills)

        super().__init__(app)

    def _build_a2a_docs(
        self,
        skills: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Pre-build A2A well-known documents for serving."""
        jacs_client = self._adapter._client
        if jacs_client is None:
            logger.warning(
                "a2a=True but no JacsClient available; "
                "A2A discovery documents will not be served"
            )
            return

        try:
            from ..a2a import JACSA2AIntegration

            integration = JACSA2AIntegration(jacs_client)

            agent_json_str = jacs_client._agent.get_agent_json()
            agent_data: Dict[str, Any] = json.loads(agent_json_str)

            if skills:
                agent_data["jacsServices"] = skills

            card = integration.export_agent_card(agent_data)
            card_dict = integration.agent_card_to_dict(card)
            extension_dict = integration.create_extension_descriptor()

            # Build the full set
            public_key_b64 = agent_data.get("jacsPublicKey", "")
            well_known = integration.generate_well_known_documents(
                agent_card=card,
                jws_signature="",
                public_key_b64=public_key_b64 or "",
                agent_data=agent_data,
            )
            # Override with our clean versions
            well_known["/.well-known/agent-card.json"] = card_dict
            well_known["/.well-known/jacs-extension.json"] = extension_dict

            self._a2a_docs = well_known
        except Exception as e:
            logger.warning("Failed to build A2A documents: %s", e)

    _CORS_HEADERS = {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, OPTIONS",
        "access-control-allow-headers": "Content-Type, Authorization",
        "cache-control": "public, max-age=3600",
    }

    async def dispatch(self, request: Request, call_next):
        # --- Serve cached A2A well-known documents ---
        if self._a2a_docs and request.url.path.startswith("/.well-known/"):
            doc = self._a2a_docs.get(request.url.path)
            if doc is not None:
                content = json.dumps(doc).encode("utf-8")
                headers = {
                    **self._CORS_HEADERS,
                    "content-length": str(len(content)),
                }
                return Response(
                    content=content,
                    status_code=200,
                    headers=headers,
                    media_type="application/json",
                )

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
