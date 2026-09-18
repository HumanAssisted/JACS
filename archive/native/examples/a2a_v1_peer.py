#!/usr/bin/env python3
"""Finite local A2A 1.0 proof against pinned official a2a-python 1.1.4.

Build the native example first; pass it explicitly with --native-bin. No mail,
model, remote signing or production host. Private identities are discarded by
its fixture command before the independent peer process starts.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import uuid

import httpx
import jwt
from google.protobuf.json_format import ParseDict, ParseError
from jwt import PyJWK
from a2a.client.card_resolver import A2ACardResolver
from a2a.client.client import ClientConfig
from a2a.client.client_factory import ClientFactory
from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.request_handlers.default_request_handler_v2 import (
    DefaultRequestHandlerV2,
)
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.types import (
    AgentCard,
    Artifact,
    Message,
    Part,
    Role,
    SendMessageRequest,
    Task,
    TaskState,
    TaskStatus,
)
from a2a.utils.proto_utils import validate_proto_required_fields
from a2a.utils.signing import create_signature_verifier, InvalidSignaturesError
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

PIN = "2d4d3048b245d2af854bad804f0e722ea9febc08"
EXTENSION = "urn:jacs:provenance-v1"
CARD = "/.well-known/agent-card.json"
BINDING = "/.well-known/jacs-compat-binding.json"
LIMIT = 1_048_576


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def peer_identity():
    dist = importlib.metadata.distribution("a2a-sdk")
    source = json.loads(dist.read_text("direct_url.json") or "{}")
    require(dist.version == "1.1.4", "This proof requires SDK1.1.4")
    require(
        source.get("vcs_info", {}).get("commit_id") == PIN,
        "Install the exact official SDK source pin",
    )
    return {"sdk_version": dist.version, "sdk_commit": PIN}


def child_env(root):
    root.mkdir(parents=True, exist_ok=True)
    return {
        "PATH": os.defpath,
        "HOME": str(root),
        "TMPDIR": str(root),
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_DATA_HOME": str(root / "data"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "JACS_USE_KEYCHAIN": "false",
        "JACS_ALLOW_NETWORK": "false",
        "JACS_ALLOW_REMOTE_KEY_LOOKUP": "false",
        "RUST_LOG": "off",
    }


def native(binary, root, operation, payload=None, url=None):
    command = [str(binary), operation] + ([url] if url else [])
    result = subprocess.run(
        command,
        input=None if payload is None else json.dumps(payload).encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=root,
        env=child_env(root),
        timeout=60,
    )
    require(result.returncode == 0, "Native helper refused its operation")
    require(len(result.stdout) <= LIMIT, "Native response exceeds bound")
    return json.loads(result.stdout)


def parse_card(wire):
    card = ParseDict(copy.deepcopy(wire), AgentCard(), ignore_unknown_fields=False)
    validate_proto_required_fields(card)
    require(len(card.supported_interfaces) == 1, "Expected one finite interface")
    interface = card.supported_interfaces[0]
    require(
        interface.protocol_version == "1.0" and interface.protocol_binding == "JSONRPC",
        "Wrong wire profile",
    )
    require(len(card.signatures) == 1, "Expected one card signature")
    extensions = [
        e for e in wire["capabilities"].get("extensions", []) if e["uri"] == EXTENSION
    ]
    require(len(extensions) == 1, "Missing/ambiguous provenance extension")
    return card


def card_verifier(jwk):
    expected_kid = jwk["kid"]
    key = PyJWK.from_dict(jwk, algorithm="ES256")

    def key_provider(kid, jku):
        require(kid == expected_kid and jku is None, "Untrusted key reference")
        return key

    official = create_signature_verifier(key_provider, algorithms=["ES256"])

    def verify(card):
        require(len(card.signatures) == 1, "Missing/ambiguous signature")
        sig = card.signatures[0]
        header = json.loads(
            base64.urlsafe_b64decode(sig.protected + "=" * (-len(sig.protected) % 4))
        )
        require(
            header == {"alg": "ES256", "kid": expected_kid, "typ": "JOSE"},
            "Unexpected protected header",
        )
        require(not sig.header, "Unexpected unprotected header")
        official(card)

    return verify


class ReportExecutor(AgentExecutor):
    def __init__(self, report):
        self.report = report
        self.requests = 0

    async def execute(self, context, event_queue):
        self.requests += 1
        require(self.requests == 1, "Finite example permits one request")
        await event_queue.enqueue_event(
            Task(
                id=context.task_id,
                context_id=context.context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_COMPLETED),
                artifacts=[
                    Artifact(
                        artifact_id="synthetic-report",
                        parts=[
                            Part(
                                raw=self.report,
                                filename="report.jacs.json",
                                media_type="application/json",
                            )
                        ],
                        extensions=[EXTENSION],
                    )
                ],
            )
        )

    async def cancel(self, context, event_queue):
        raise RuntimeError("Finite completed report has no cancellation flow")


class BoundedHTTP(httpx.AsyncBaseTransport):
    """Bound received bytes before handing a response to the stock SDK."""

    def __init__(self):
        self.inner = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request):
        response = await self.inner.handle_async_request(request)
        chunks, size = [], 0
        try:
            async for chunk in response.aiter_raw():
                size += len(chunk)
                require(size <= LIMIT, "HTTP response exceeds bound")
                chunks.append(chunk)
            return httpx.Response(
                response.status_code,
                headers=response.headers,
                content=b"".join(chunks),
                request=request,
            )
        finally:
            await response.aclose()

    async def aclose(self):
        await self.inner.aclose()


class BoundedBody:
    """Reject oversized local requests before the SDK dispatcher parses them."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > LIMIT:
                await send(
                    {"type": "http.response.start", "status": 413, "headers": []}
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": b"Request exceeds example limit",
                    }
                )
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        first = True

        async def buffered():
            nonlocal first
            if first:
                first = False
                return {
                    "type": "http.request",
                    "body": b"".join(chunks),
                    "more_body": False,
                }
            return await receive()

        await self.app(scope, buffered, send)


async def recipient(binary, packet_path, base_url, root):
    identity = peer_identity()
    packet = json.loads(packet_path.read_text())
    require(not any(root.iterdir()), "Recipient home must start empty")
    child_env(root)
    expected_interface = base_url + "/a2a"
    visited = []

    async def before(request):
        require(
            str(request.url).startswith(base_url + "/"),
            "Network outside exact loopback origin",
        )
        visited.append((request.method, str(request.url)))

    async with httpx.AsyncClient(
        trust_env=False,
        timeout=10,
        follow_redirects=False,
        event_hooks={"request": [before]},
        transport=BoundedHTTP(),
    ) as http:
        responses = [
            await http.get(base_url + path)
            for path in [CARD, BINDING, "/.well-known/jwks.json"]
        ]
        for response in responses:
            response.raise_for_status()
        wire, binding, jwks = [response.json() for response in responses]
        card = parse_card(wire)
        require(
            card.supported_interfaces[0].url == expected_interface,
            "Advertised endpoint differs from served endpoint",
        )
        require(wire == packet["card"], "Discovery changed the signed card")
        require(len(jwks["keys"]) == 1, "Ambiguous JWKS")
        verified_input = {
            **packet,
            "card": wire,
            "binding": binding,
            "jwk": jwks["keys"][0],
        }
        native_result = native(binary, root, "verify", verified_input)
        require(
            native_result["native_binding_valid"],
            "Native root binding refused; card key is untrusted",
        )
        verify = card_verifier(jwks["keys"][0])
        # Use the normal official HTTP resolver with signature verification ON.
        resolved = await A2ACardResolver(http, base_url).get_agent_card(
            signature_verifier=verify
        )
        require(resolved == card, "Resolver changed the selected v1 card")
        client = ClientFactory(
            ClientConfig(
                httpx_client=http,
                streaming=False,
                supported_protocol_bindings=["JSONRPC"],
                accepted_output_modes=["application/json"],
            )
        ).create(resolved)
        events = [
            event
            async for event in client.send_message(
                SendMessageRequest(
                    message=Message(
                        message_id=str(uuid.uuid4()),
                        role=Role.ROLE_USER,
                        parts=[Part(text="Return the synthetic report")],
                    )
                )
            )
        ]
        require(
            len(events) == 1 and events[0].HasField("task"),
            "Expected one finite task response",
        )
        task = events[0].task
        require(
            task.status.state == TaskState.TASK_STATE_COMPLETED
            and len(task.artifacts) == 1,
            "Task did not finish with one artifact",
        )
        artifact = task.artifacts[0]
        require(
            list(artifact.extensions) == [EXTENSION] and len(artifact.parts) == 1,
            "Unexpected artifact shape",
        )
        part = artifact.parts[0]
        require(
            part.WhichOneof("content") == "raw"
            and part.media_type == "application/json",
            "Expected exact raw JSON bytes",
        )
        received = bytes(part.raw)
        require(
            received == packet["report"].encode(), "Artifact bytes changed in transport"
        )
        received_input = {**verified_input, "report": received.decode()}
        accepted = native(binary, root, "verify", received_input)
        require(
            accepted["native_binding_valid"]
            and accepted["native_report_integrity_valid"],
            "Native report verification refused",
        )
        require(
            ("POST", expected_interface) in visited,
            "Client never called returned interface",
        )

    refused = []
    for vector in packet["vectors"]:
        verify(parse_card(vector["card"]))
    require(wire["capabilities"]["streaming"] is False, "Optional false lost presence")
    require(
        "required" not in wire["capabilities"]["extensions"][0],
        "Ordinary false was not omitted",
    )
    require(
        "streaming" not in packet["vectors"][1]["card"]["capabilities"],
        "Absent optional gained presence",
    )

    # Mutations go to the unmodified official signature verifier, never a mock.
    for case in [
        "card_content",
        "card_signature",
        "wrong_algorithm",
        "wrong_card_key",
        "unknown_wire_field",
    ]:
        altered = copy.deepcopy(wire)
        verifier = verify
        if case == "card_content":
            altered["description"] += " tampered"
        elif case == "card_signature":
            sig = altered["signatures"][0]["signature"]
            altered["signatures"][0]["signature"] = (
                "A" if sig[0] != "A" else "B"
            ) + sig[1:]
        elif case == "wrong_algorithm":
            header = {"alg": "HS256", "kid": packet["jwk"]["kid"], "typ": "JOSE"}
            altered["signatures"][0]["protected"] = (
                base64.urlsafe_b64encode(json.dumps(header).encode())
                .decode()
                .rstrip("=")
            )
        elif case == "wrong_card_key":
            from cryptography.hazmat.primitives.asymmetric import ec

            wrong = json.loads(
                jwt.algorithms.ECAlgorithm.to_jwk(
                    ec.generate_private_key(ec.SECP256R1()).public_key()
                )
            )
            wrong["kid"] = packet["jwk"]["kid"]
            verifier = card_verifier(wrong)
        else:
            altered["unknown"] = "must not be silently discarded"
        try:
            verifier(parse_card(altered))
        except (
            RuntimeError,
            InvalidSignaturesError,
            ValueError,
            ParseError,
            jwt.PyJWTError,
        ):
            refused.append(case)
        else:
            raise RuntimeError("Card negative accepted: " + case)

    for case in [
        "wrong_root",
        "wrong_jwk",
        "missing_hash",
        "changed_hash",
        "duplicate_extension",
        *packet["negativeBindings"],
    ]:
        altered = copy.deepcopy(received_input)
        params = altered["card"]["capabilities"]["extensions"][0]["params"]
        if case in packet["negativeBindings"]:
            altered["binding"] = packet["negativeBindings"][case]
            params["jacsCompatBindingHash"] = altered["binding"]["jacsSha256"]
        elif case == "wrong_root":
            altered["trustedRoot"] = [0] * 32
        elif case == "wrong_jwk":
            altered["jwk"]["x"] = "A" * 43
        elif case == "missing_hash":
            del params["jacsCompatBindingHash"]
        elif case == "changed_hash":
            params["jacsCompatBindingHash"] = "bad"
        else:
            altered["card"]["capabilities"]["extensions"].append(
                copy.deepcopy(altered["card"]["capabilities"]["extensions"][0])
            )
        require(
            not native(binary, root, "verify", altered)["native_binding_valid"],
            "Binding negative accepted: " + case,
        )
        refused.append(case)
    tampered = copy.deepcopy(received_input)
    report = json.loads(tampered["report"])
    report["content"]["score"] = 8
    tampered["report"] = json.dumps(report)
    require(
        not native(binary, root, "verify", tampered)["native_report_integrity_valid"],
        "Tampered report accepted",
    )
    refused.append("tampered_report")
    require(not any(root.iterdir()), "Recipient native verification wrote state")
    return {
        **identity,
        **accepted,
        "protocol": "1.0",
        "recipient_pid": os.getpid(),
        "returned_interface_called": expected_interface,
        "artifact_bytes_preserved": True,
        "artifact_sha256": sha(received),
        "artifact_size": len(received),
        "card_vectors_verified": len(packet["vectors"]),
        "refused": refused,
        "typed_profile_refusals": packet["rejectedProfiles"],
        "recipient_has_no_private_identity": True,
    }


async def driver(binary):
    peer_identity()
    script = Path(__file__).resolve()
    binary_hash = sha(binary.read_bytes())
    with tempfile.TemporaryDirectory(prefix="jacs-a2a-peer-") as temp:
        work = Path(temp).resolve()
        home = work / "native-home"
        home.mkdir(mode=0o700)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        base_url = "http://127.0.0.1:" + str(sock.getsockname()[1])
        try:
            packet = native(binary, home, "fixture", url=base_url + "/a2a")
            require(
                not any(home.iterdir()), "Fixture private workspace was not removed"
            )
            card = parse_card(packet["card"])
            executor = ReportExecutor(packet["report"].encode())
            handler = DefaultRequestHandlerV2(executor, InMemoryTaskStore(), card)

            async def discovery(request):
                value = {
                    CARD: packet["card"],
                    BINDING: packet["binding"],
                    "/.well-known/jwks.json": {"keys": [packet["jwk"]]},
                }[request.url.path]
                return JSONResponse(value, headers={"Cache-Control": "no-store"})

            routes = [
                Route(path, discovery, methods=["GET"])
                for path in [CARD, BINDING, "/.well-known/jwks.json"]
            ]
            routes += create_jsonrpc_routes(handler, "/a2a", enable_v0_3_compat=False)
            server = uvicorn.Server(
                uvicorn.Config(
                    BoundedBody(Starlette(routes=routes)),
                    log_level="critical",
                    access_log=False,
                    timeout_graceful_shutdown=5,
                    lifespan="off",
                )
            )
            serving = asyncio.create_task(server.serve(sockets=[sock]))
            proc = None
            try:
                async with asyncio.timeout(10):
                    while not server.started:
                        if serving.done():
                            await serving
                            raise RuntimeError("Host exited before ready")
                        await asyncio.sleep(0.02)
                packet_path = work / "public-packet.json"
                packet_path.write_text(json.dumps(packet))
                recipient_home = work / "recipient"
                recipient_home.mkdir(mode=0o700)
                proc = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-I",
                    str(script),
                    "--native-bin",
                    str(binary),
                    "--recipient",
                    str(packet_path),
                    "--origin",
                    base_url,
                    "--recipient-home",
                    str(recipient_home),
                    cwd=recipient_home,
                    env=child_env(recipient_home),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), 90)
                require(
                    proc.returncode == 0,
                    "Official peer subprocess failed: " + stderr.decode()[-1000:],
                )
                result = json.loads(stdout)
                require(
                    result["recipient_pid"] != os.getpid() and executor.requests == 1,
                    "Process/finite request contract failed",
                )
            finally:
                if proc is not None and proc.returncode is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    await proc.wait()
                server.should_exit = True
                await asyncio.wait_for(serving, 10)
                await handler.aclose()
        finally:
            sock.close()
    require(
        sha(binary.read_bytes()) == binary_hash, "Native binary changed during proof"
    )
    return {
        **result,
        "driver_pid": os.getpid(),
        "native_binary_sha256": binary_hash,
        "harness_sha256": sha(script.read_bytes()),
        "private_keys_removed_before_peer": True,
        "temporary_files_cleaned": not work.exists(),
        "host_shutdown_clean": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-bin", type=Path, required=True)
    parser.add_argument("--recipient", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--origin", help=argparse.SUPPRESS)
    parser.add_argument("--recipient-home", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = args.native_bin.resolve(strict=True)
    if args.recipient:
        result = asyncio.run(
            recipient(binary, args.recipient, args.origin, args.recipient_home)
        )
    else:
        result = asyncio.run(driver(binary))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
