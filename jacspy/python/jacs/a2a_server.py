"""
A2A Server — FastAPI routes for well-known A2A discovery documents.

Provides ``jacs_a2a_routes()`` which returns an ``APIRouter`` serving
all five ``.well-known`` endpoints required for A2A agent discovery,
plus a top-level ``serve_a2a()`` convenience function.

Usage — mount into an existing app::

    from fastapi import FastAPI
    from jacs.client import JacsClient
    from jacs.a2a_server import jacs_a2a_routes

    app = FastAPI()
    client = JacsClient.quickstart()
    app.include_router(jacs_a2a_routes(client))

Usage — standalone server::

    from jacs.client import JacsClient
    from jacs.a2a_server import serve_a2a

    client = JacsClient.quickstart()
    serve_a2a(client, port=8080)

Requires ``fastapi`` and ``uvicorn``.  Install with ``pip install jacs[fastapi]``.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

try:
    from fastapi import APIRouter, FastAPI, Query
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
except ImportError as _exc:
    raise ImportError(
        "jacs.a2a_server requires fastapi. "
        "Install it with: pip install jacs[fastapi]"
    ) from _exc

if TYPE_CHECKING:
    from .client import JacsClient

logger = logging.getLogger("jacs.a2a_server")


def jacs_a2a_routes(
    client: "JacsClient",
    skills: Optional[List[Dict[str, Any]]] = None,
) -> APIRouter:
    """Build a FastAPI ``APIRouter`` serving A2A well-known documents.

    The router exposes five endpoints under ``/.well-known/``:

    - ``agent-card.json`` — A2A Agent Card (v0.4.0)
    - ``jwks.json`` — JWK Set for external verifiers
    - ``jacs-agent.json`` — JACS agent descriptor
    - ``jacs-pubkey.json`` — JACS public key
    - ``jacs-extension.json`` — JACS provenance extension descriptor

    All responses include CORS headers for cross-origin discovery.

    Args:
        client: A loaded ``JacsClient`` instance.
        skills: Optional list of raw JACS service dicts.  When supplied,
            they override the agent's own ``jacsServices`` for the
            exported agent card.

    Returns:
        A ``fastapi.APIRouter`` ready to be included via
        ``app.include_router()``.
    """
    from .a2a import JACSA2AIntegration

    router = APIRouter(tags=["A2A Discovery"])

    # Build static documents once at mount time.
    integration = JACSA2AIntegration(client)

    try:
        agent_json_str = client._agent.get_agent_json()
        agent_data: Dict[str, Any] = json.loads(agent_json_str)
    except Exception as e:
        raise RuntimeError(
            f"Cannot build A2A routes: failed to read agent JSON: {e}"
        ) from e

    if skills:
        agent_data["jacsServices"] = skills

    card = integration.export_agent_card(agent_data)
    card_dict = integration.agent_card_to_dict(card)
    extension_dict = integration.create_extension_descriptor()

    # Build the full well-known document set if we can; otherwise
    # serve what we have (agent card + extension are always available).
    try:
        public_key_b64 = agent_data.get("jacsPublicKey", "")
        if not public_key_b64:
            # Try reading from the agent's key file path
            info = client._agent_info
            if info and getattr(info, "public_key_path", None):
                import base64
                with open(info.public_key_path, "rb") as f:
                    public_key_b64 = base64.b64encode(f.read()).decode("utf-8")

        well_known_docs = integration.generate_well_known_documents(
            agent_card=card,
            jws_signature="",  # JWS signing deferred to full setup
            public_key_b64=public_key_b64 or "",
            agent_data=agent_data,
        )
    except Exception:
        logger.debug("Could not generate full well-known set; serving partial")
        well_known_docs = {
            "/.well-known/agent-card.json": card_dict,
            "/.well-known/jacs-extension.json": extension_dict,
        }

    # Override agent-card with our freshly-built version (it may have
    # a JWS stub from generate_well_known_documents).
    well_known_docs["/.well-known/agent-card.json"] = card_dict
    well_known_docs["/.well-known/jacs-extension.json"] = extension_dict

    # --- Route handlers ---

    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Cache-Control": "public, max-age=3600",
    }

    def _json_response(content: Any) -> JSONResponse:
        return JSONResponse(content=content, headers=cors_headers)

    @router.get("/.well-known/agent-card.json")
    def agent_card_endpoint(signed: Optional[str] = Query(default=None)):
        """Return the A2A Agent Card.

        Pass ``?signed=true`` to get the card with a JWS signature
        envelope (if available).
        """
        if signed and signed.lower() == "true":
            # Return the version from generate_well_known_documents
            # which may include a signatures field.
            full_card = well_known_docs.get(
                "/.well-known/agent-card.json", card_dict
            )
            return _json_response(full_card)
        return _json_response(card_dict)

    @router.get("/.well-known/jwks.json")
    def jwks_endpoint():
        """Return the JWK Set for external verifiers."""
        content = well_known_docs.get("/.well-known/jwks.json", {"keys": []})
        return _json_response(content)

    @router.get("/.well-known/jacs-agent.json")
    def jacs_agent_endpoint():
        """Return the JACS agent descriptor."""
        content = well_known_docs.get("/.well-known/jacs-agent.json", {})
        return _json_response(content)

    @router.get("/.well-known/jacs-pubkey.json")
    def jacs_pubkey_endpoint():
        """Return the JACS public key document."""
        content = well_known_docs.get("/.well-known/jacs-pubkey.json", {})
        return _json_response(content)

    @router.get("/.well-known/jacs-extension.json")
    def jacs_extension_endpoint():
        """Return the JACS provenance extension descriptor."""
        return _json_response(extension_dict)

    return router


def create_a2a_app(
    client: "JacsClient",
    skills: Optional[List[Dict[str, Any]]] = None,
    title: str = "JACS A2A Agent",
) -> FastAPI:
    """Create a full FastAPI application with A2A routes and CORS.

    Args:
        client: A loaded ``JacsClient`` instance.
        skills: Optional skill overrides.
        title: Application title.

    Returns:
        A configured ``FastAPI`` app.
    """
    app = FastAPI(title=title)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

    router = jacs_a2a_routes(client, skills=skills)
    app.include_router(router)

    return app


def serve_a2a(
    client: "JacsClient",
    port: int = 8080,
    host: str = "0.0.0.0",
    skills: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Start a standalone A2A discovery server.

    Creates a FastAPI application with all well-known endpoints and
    runs it with uvicorn.  This is a **blocking** call intended for
    quick demos and local development.

    For production use, call ``jacs_a2a_routes()`` and mount the router
    into your own ASGI application.

    Args:
        client: A loaded ``JacsClient`` instance.
        port: TCP port to listen on (default 8080).
        host: Bind address (default ``"0.0.0.0"``).
        skills: Optional skill overrides for the agent card.
    """
    try:
        import uvicorn
    except ImportError as exc:
        raise ImportError(
            "serve_a2a() requires uvicorn. "
            "Install it with: pip install jacs[fastapi]"
        ) from exc

    app = create_a2a_app(client, skills=skills)
    uvicorn.run(app, host=host, port=port)


__all__ = [
    "jacs_a2a_routes",
    "create_a2a_app",
    "serve_a2a",
]
