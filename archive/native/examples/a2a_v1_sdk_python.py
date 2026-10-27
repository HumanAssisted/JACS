#!/usr/bin/env python3
"""Public Python v1 discovery + official a2a-sdk 1.3.0 ES256 HTTP exchange.

The default native root stays ML-DSA-87. ES256 is explicitly selected for the
stock Python SDK's signing backend; no automatic downgrade or patched SDK.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import uuid

import httpx
from a2a.client.card_resolver import A2ACardResolver
from a2a.client.client import ClientConfig
from a2a.client.client_factory import ClientFactory
from a2a.server.request_handlers.default_request_handler_v2 import DefaultRequestHandlerV2
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

from a2a_v1_peer import (
    BINDING, CARD, BoundedBody, BoundedHTTP, ReportExecutor, card_verifier,
    native, parse_card, peer_identity, require, sha,
)


def fixture(messaging_url):
    from jacs.client import JacsClient

    with tempfile.TemporaryDirectory(prefix="jacs-python-a2a-sdk-") as temp:
        # A process-local, generated secret; never a command argument or output.
        os.environ["JACS_PRIVATE_KEY_PASSWORD"] = "Synthetic!9aA" + secrets.token_hex(32)
        try:
            with JacsClient.quickstart(
                name="Public Python café 雪", domain="example.test",
                description="Finite report using an explicitly selected compatibility key",
                algorithm="pq2025", config_path=str(Path(temp).resolve() / "jacs.config.json"),
            ) as sender:
                trusted_root = base64.b64decode(re.sub(
                    r"-----[^-]+-----|\s", "", sender.get_public_key()
                ))
                require(len(trusted_root) == 2592, "Expected ML-DSA-87 native root")
                identity = json.loads(sender.export_agent())
                profile = {
                    "protocolVersion": "1.0", "messagingUrl": messaging_url,
                    "skills": [{"id": "python-sdk-report", "name": "Public Python SDK report",
                                "description": "Return one pre-signed JSON report", "tags": ["provenance"]}],
                    "defaultInputModes": ["text/plain"],
                    "defaultOutputModes": ["application/json"],
                }
                documents = sender.get_a2a().generate_well_known_documents(
                    a2a_algorithm="ES256", discovery_options=profile,
                )
                require(BINDING in documents, "Explicit compatibility binding missing")
                packet = {
                    "card": documents[CARD], "jwk": documents["/.well-known/jwks.json"]["keys"][0],
                    "binding": documents[BINDING], "trustedRoot": list(trusted_root),
                    "expectedId": sender.agent_id, "expectedVersion": identity["jacsVersion"],
                    "rootAlgorithm": "pq2025",
                    "report": sender.sign_message({"report": "Synthetic café 雪", "score": 7}).raw_json,
                }
        finally:
            os.environ.pop("JACS_PRIVATE_KEY_PASSWORD", None)
    return packet  # All private files and the signing client are gone.


async def run(binary):
    sdk = peer_identity()
    with tempfile.TemporaryDirectory(prefix="jacs-python-sdk-peer-") as temp:
        work = Path(temp).resolve()
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
        try:
            produced = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--fixture-url", origin + "/a2a"],
                env={**os.environ, "JACS_USE_KEYCHAIN": "false", "JACS_ALLOW_NETWORK": "false",
                     "JACS_ALLOW_REMOTE_KEY_LOOKUP": "false", "RUST_LOG": "off"},
                capture_output=True, text=True, timeout=120,
            )
            require(produced.returncode == 0, "Public Python export failed: " + produced.stderr[-2000:])
            require(len(produced.stdout) < 1_048_576, "Oversized public fixture")
            packet = json.loads(produced.stdout)
            trusted = native(binary, work / "verifier", "verify", packet)
            require(trusted["native_binding_valid"] and trusted["native_report_integrity_valid"],
                    "Native PQ root/binding/report validation failed")
            card = parse_card(packet["card"])
            require(card.skills[0].id == "python-sdk-report", "Caller skill was replaced")
            verify = card_verifier(packet["jwk"])
            verify(card)  # Stock SDK/PyJWT ES256 verification, independent of JACS.
            executor = ReportExecutor(packet["report"].encode())
            handler = DefaultRequestHandlerV2(executor, InMemoryTaskStore(), card)

            async def discovery(request):
                value = {CARD: packet["card"], BINDING: packet["binding"],
                         "/.well-known/jwks.json": {"keys": [packet["jwk"]]}}[request.url.path]
                return JSONResponse(value, headers={"Cache-Control": "no-store"})

            routes = [Route(path, discovery) for path in [CARD, BINDING, "/.well-known/jwks.json"]]
            routes += create_jsonrpc_routes(handler, "/a2a", enable_v0_3_compat=False)
            server = uvicorn.Server(uvicorn.Config(
                BoundedBody(Starlette(routes=routes)), log_level="critical", access_log=False,
                lifespan="off", timeout_graceful_shutdown=5,
            ))
            serving = asyncio.create_task(server.serve(sockets=[sock]))
            try:
                async with asyncio.timeout(10):
                    while not server.started:
                        if serving.done():
                            await serving
                            raise RuntimeError("Server exited before ready")
                        await asyncio.sleep(0.02)
                async with httpx.AsyncClient(trust_env=False, timeout=10, transport=BoundedHTTP()) as http:
                    resolved = await A2ACardResolver(http, origin).get_agent_card(signature_verifier=verify)
                    require(resolved.supported_interfaces[0].url == origin + "/a2a", "Wrong interface")
                    client = ClientFactory(ClientConfig(
                        httpx_client=http, streaming=False, supported_protocol_bindings=["JSONRPC"],
                        accepted_output_modes=["application/json"],
                    )).create(resolved)
                    events = [event async for event in client.send_message(SendMessageRequest(
                        message=Message(message_id=str(uuid.uuid4()), role=Role.ROLE_USER,
                                        parts=[Part(text="Return the synthetic report")]),
                    ))]
                require(len(events) == 1 and events[0].HasField("task"), "Expected one task")
                task = events[0].task
                require(task.status.state == TaskState.TASK_STATE_COMPLETED and executor.requests == 1,
                        "The actual SDK interface did not complete exactly one request")
                received = bytes(task.artifacts[0].parts[0].raw)
                require(received == packet["report"].encode(), "Artifact bytes changed")
            finally:
                server.should_exit = True
                await asyncio.wait_for(serving, 10)
                await handler.aclose()

            refused = []
            for name in ["card_content", "card_signature"]:
                altered = copy.deepcopy(packet["card"])
                if name == "card_content":
                    altered["description"] += " tampered"
                else:
                    signature = bytearray(base64.urlsafe_b64decode(altered["signatures"][0]["signature"] + "=="))
                    signature[0] ^= 1
                    altered["signatures"][0]["signature"] = base64.urlsafe_b64encode(signature).decode().rstrip("=")
                try:
                    verify(parse_card(altered))
                except Exception:
                    refused.append(name)
                else:
                    raise RuntimeError("Official SDK accepted " + name)
            for name in ["wrong_root", "wrong_identity", "wrong_binding_hash"]:
                altered = copy.deepcopy(packet)
                if name == "wrong_root":
                    altered["trustedRoot"][0] ^= 1
                elif name == "wrong_identity":
                    altered["expectedId"] = str(uuid.uuid4())
                else:
                    altered["card"]["capabilities"]["extensions"][0]["params"]["jacsCompatBindingHash"] = "bad"
                require(not native(binary, work / "verifier", "verify", altered)["native_binding_valid"],
                        "Native verifier accepted " + name)
                refused.append(name)
            print(json.dumps({**sdk, "protocol": "1.0", "native_root_algorithm": "ML-DSA-87",
                              "public_binding_used": True, "stock_sdk_signature_verified": True,
                              "returned_interface_called": True, "artifact_bytes_preserved": True,
                              "artifact_sha256": sha(received), "refused": refused,
                              "private_identity_removed_before_peer": True}, sort_keys=True))
        finally:
            sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-bin", type=Path)
    parser.add_argument("--fixture-url", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.fixture_url:
        print(json.dumps(fixture(args.fixture_url)))
    else:
        if not args.native_bin:
            parser.error("--native-bin is required")
        asyncio.run(run(args.native_bin.resolve(strict=True)))


if __name__ == "__main__":
    main()
