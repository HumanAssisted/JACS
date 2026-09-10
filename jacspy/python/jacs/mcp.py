"""JACS MCP (Model Context Protocol) Integration.

Provides both class-based and simplified wrappers for adding JACS
cryptographic signing and verification to MCP transports and servers.

Quick start (simple API):
    from jacs.mcp import create_jacs_mcp_server
    mcp = create_jacs_mcp_server(
        "My Server",
        "./jacs.config.json",
        allowed_peer_agent_ids=["EXPECTED_CLIENT_AGENT_ID"],
    )
    mcp.run(transport="sse")

Class-based client:
    from jacs.mcp import JACSMCPClient
    client = JACSMCPClient(
        "http://localhost:8000/sse",
        "jacs.config.json",
        expected_peer_agent_id="EXPECTED_SERVER_AGENT_ID",
    )
    async with client:
        result = await client.call_tool("my_tool", {"arg": "value"})

Class-based server:
    from jacs.mcp import JACSMCPServer
    from fastmcp import FastMCP
    mcp = FastMCP("My Server")
    mcp = JACSMCPServer(
        mcp,
        "jacs.config.json",
        allowed_peer_agent_ids=["EXPECTED_CLIENT_AGENT_ID"],
    )

    # For HTTP deployment with uvicorn:
    app = mcp.http_app(transport="sse")
    # uvicorn.run(app, host="localhost", port=8000)

Requires (optional): fastmcp, mcp, starlette
"""

import contextlib
import ipaddress
import json
import logging
import os
import uuid
from typing import Any, Callable, Dict, Iterable, Optional
from functools import wraps
from urllib.parse import urlparse

from . import simple
from ._signed_document import require_portable_v2_signed_raw


def _resolve_strict(strict: Optional[bool] = None) -> bool:
    """Return True if strict mode is active (parameter or env var)."""
    env_strict = os.environ.get("JACS_STRICT_MODE", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    return strict is True or env_strict


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
        return allow_unsigned_fallback is True
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


def _secure_server_transport(transport: Optional[str]) -> str:
    """Resolve server entrypoints to a middleware-capable HTTP transport."""
    resolved = transport or "sse"
    if resolved == "stdio":
        raise simple.ConfigError(
            "Python JACS MCP authentication requires an HTTP transport; "
            "stdio bypasses the signing middleware. Use transport='sse' or "
            "transport='streamable-http'."
        )
    if resolved not in ("sse", "http", "streamable-http"):
        raise simple.ConfigError(f"Unsupported JACS MCP transport: {resolved}")
    return resolved


try:
    from jacs import JacsAgent
except ImportError:
    JacsAgent = None  # type: ignore[assignment, misc]

try:
    from fastmcp import Client
    from fastmcp.client.transports import SSETransport
except ImportError:
    Client = None  # type: ignore[assignment, misc]
    SSETransport = None  # type: ignore[assignment, misc]

_JacsSSETransportBase = SSETransport if SSETransport is not None else object

try:
    from mcp.client.sse import sse_client
    from mcp import ClientSession
except ImportError:
    sse_client = None  # type: ignore[assignment]
    ClientSession = None  # type: ignore[assignment, misc]

try:
    from starlette.responses import Response, JSONResponse, StreamingResponse
except ImportError:
    Response = None  # type: ignore[assignment, misc]
    JSONResponse = None  # type: ignore[assignment, misc]
    StreamingResponse = None  # type: ignore[assignment, misc]


LOGGER = logging.getLogger("jacs.mcp")

JACS_MCP_SIGNED_CARRIER_METHOD = "notifications/jacs/signed"
JACS_MCP_SIGNED_CARRIER_VERSION = 1
_JACS_MCP_CARRIER_KEYS = frozenset(("jsonrpc", "method", "params"))
_JACS_MCP_CARRIER_PARAM_KEYS = frozenset(("version", "envelope"))
MAX_SIGNED_SSE_EVENT_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_MCP_MESSAGE_BYTES = 2 * 1024 * 1024
MAX_PENDING_MCP_REQUESTS = 4096


class _MCPMessageTooLarge(ValueError):
    """A bounded MCP HTTP message exceeded the configured hard limit."""


def _resolve_max_message_bytes(value: Optional[int] = None) -> int:
    """Resolve the HTTP body cap from an explicit value or environment."""
    if value is None:
        raw = os.environ.get("JACS_MCP_MAX_MESSAGE_BYTES", "").strip()
        if raw:
            try:
                value = int(raw)
            except ValueError as exc:
                raise simple.ConfigError(
                    "JACS_MCP_MAX_MESSAGE_BYTES must be a positive integer"
                ) from exc
        else:
            value = DEFAULT_MAX_MCP_MESSAGE_BYTES
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise simple.ConfigError("MCP max_message_bytes must be a positive integer")
    return value


def _resolve_peer_policy(
    *,
    expected_peer_agent_id: Optional[str] = None,
    expected_peer_public_key_hash: Optional[str] = None,
    allowed_peer_agent_ids: Optional[Iterable[str]] = None,
    allow_any_verified_peer: Optional[bool] = None,
    context: str,
    require_policy: bool = True,
):
    """Resolve an explicit signer policy for an authenticated MCP boundary."""
    configured_ids = set()
    expected = expected_peer_agent_id
    if expected is None:
        expected = os.environ.get("JACS_MCP_EXPECTED_PEER_AGENT_ID")
    if expected is not None:
        if (
            not isinstance(expected, str)
            or not expected
            or expected != expected.strip()
        ):
            raise simple.ConfigError(f"{context}: expected peer agent ID is invalid")
        configured_ids.add(expected)

    allowed = allowed_peer_agent_ids
    if allowed is None:
        raw_allowed = os.environ.get("JACS_MCP_ALLOWED_PEER_AGENT_IDS", "")
        allowed = raw_allowed.split(",") if raw_allowed.strip() else ()
    elif isinstance(allowed, str):
        allowed = (allowed,)
    allowed_values = tuple(allowed)
    if expected is not None and allowed_values:
        raise simple.ConfigError(
            f"{context}: expected_peer_agent_id and allowed_peer_agent_ids "
            "are mutually exclusive"
        )
    for peer_id in allowed_values:
        if not isinstance(peer_id, str) or not peer_id or peer_id != peer_id.strip():
            raise simple.ConfigError(f"{context}: allowed peer agent ID is invalid")
        configured_ids.add(peer_id)

    if allow_any_verified_peer is None:
        raw_allow_any = (
            os.environ.get("JACS_MCP_ALLOW_ANY_VERIFIED_PEER", "").strip().lower()
        )
        if raw_allow_any not in ("", "0", "false", "no", "1", "true", "yes"):
            raise simple.ConfigError(
                "JACS_MCP_ALLOW_ANY_VERIFIED_PEER must be a boolean"
            )
        allow_any = raw_allow_any in ("1", "true", "yes")
    else:
        if not isinstance(allow_any_verified_peer, bool):
            raise simple.ConfigError(
                f"{context}: allow_any_verified_peer must be a boolean"
            )
        allow_any = allow_any_verified_peer is True

    if allow_any and configured_ids:
        raise simple.ConfigError(
            f"{context}: allow_any_verified_peer cannot be combined with peer pins"
        )

    expected_hash = expected_peer_public_key_hash
    if expected_hash is None:
        expected_hash = os.environ.get("JACS_MCP_EXPECTED_PEER_PUBLIC_KEY_HASH")
    if expected_hash is not None:
        if (
            not isinstance(expected_hash, str)
            or not expected_hash
            or expected_hash != expected_hash.strip()
        ):
            raise simple.ConfigError(
                f"{context}: expected peer public-key hash is invalid"
            )
        if expected is None:
            raise simple.ConfigError(
                f"{context}: a public-key hash pin requires expected_peer_agent_id"
            )

    if require_policy and not configured_ids and not allow_any:
        raise simple.ConfigError(
            f"{context}: authenticated MCP requires expected_peer_agent_id or "
            "allowed_peer_agent_ids. Set allow_any_verified_peer=True only for "
            "dangerous proof-of-possession compatibility mode."
        )
    return frozenset(configured_ids), allow_any, expected_hash


def _peer_verifier(
    agent,
    allowed_peer_agent_ids,
    allow_any_verified_peer,
    expected_peer_public_key_hash=None,
):
    """Create a verifier that binds a valid envelope to an authorized signer."""

    def verify(envelope: str):
        if not allowed_peer_agent_ids and not allow_any_verified_peer:
            raise simple.ConfigError(
                "Authenticated MCP verification requires an explicit peer agent ID"
            )
        require_portable_v2_signed_raw(envelope, context="JACS MCP peer")
        signed_document = json.loads(envelope)
        signature = signed_document["jacsSignature"]
        envelope_signer_id = signature.get("agentID", signature.get("agentId"))
        envelope_key_hash = signature.get("publicKeyHash")

        result = agent.verify_response_with_agent_id(envelope)
        if not isinstance(result, tuple) or len(result) != 2:
            raise simple.VerificationError(
                "JACS peer verification returned an invalid result"
            )
        signer_id, payload = result
        if not isinstance(signer_id, str) or not signer_id:
            raise simple.VerificationError(
                "JACS peer verification omitted the signer identity"
            )
        if signer_id != envelope_signer_id:
            raise simple.VerificationError(
                "Verified MCP signer identity did not match the signed metadata"
            )
        if not allow_any_verified_peer and signer_id not in allowed_peer_agent_ids:
            raise simple.VerificationError(f"Unexpected MCP peer signer: {signer_id}")
        if (
            expected_peer_public_key_hash is not None
            and envelope_key_hash != expected_peer_public_key_hash
        ):
            raise simple.VerificationError(
                "Verified MCP peer public-key hash did not match the configured pin"
            )
        return payload

    return verify


class _RequestIdState:
    """Bind responses to one transport session using unpredictable wire IDs."""

    def __init__(self, max_pending: int = MAX_PENDING_MCP_REQUESTS):
        self._max_pending = max_pending
        self._pending: Dict[str, Any] = {}

    def prepare_outbound(self, payload: Dict[str, Any]):
        if "method" not in payload or "id" not in payload:
            return payload, None
        if len(self._pending) >= self._max_pending:
            raise simple.SigningError("Too many pending MCP requests")
        wire_id = str(uuid.uuid4())
        while wire_id in self._pending:  # pragma: no cover - UUID collision
            wire_id = str(uuid.uuid4())
        self._pending[wire_id] = payload["id"]
        rewritten = dict(payload)
        rewritten["id"] = wire_id
        return rewritten, wire_id

    def restore_inbound(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if "method" in payload or "id" not in payload:
            return payload
        wire_id = payload["id"]
        if not isinstance(wire_id, str) or wire_id not in self._pending:
            raise simple.VerificationError(
                "MCP response did not match a pending request in this session"
            )
        local_id = self._pending.pop(wire_id)
        restored = dict(payload)
        restored["id"] = local_id
        return restored

    def discard(self, wire_id: Optional[str]) -> None:
        if wire_id is not None:
            self._pending.pop(wire_id, None)

    def clear(self) -> None:
        self._pending.clear()


async def _read_bounded_request_body(request, limit: int) -> bytes:
    """Read an HTTP request body without allowing unbounded buffering."""
    headers = getattr(request, "headers", {}) or {}
    content_length = headers.get("content-length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise ValueError("Invalid MCP Content-Length header") from exc
        if declared_length > limit:
            raise _MCPMessageTooLarge("MCP request body exceeded the byte limit")

    body = bytearray()
    stream = getattr(request, "stream", None)
    if callable(stream):
        async for chunk in stream():
            body.extend(chunk)
            if len(body) > limit:
                raise _MCPMessageTooLarge("MCP request body exceeded the byte limit")
    else:  # compatibility with minimal request test doubles
        body.extend(await request.body())
        if len(body) > limit:
            raise _MCPMessageTooLarge("MCP request body exceeded the byte limit")
    value = bytes(body)
    request._body = value
    return value


async def _read_bounded_response_body(body_iterator, limit: int) -> bytes:
    """Buffer a JSON response only up to the configured signing limit."""
    body = bytearray()
    async for chunk in body_iterator:
        if not isinstance(chunk, bytes):
            chunk = str(chunk).encode("utf-8")
        body.extend(chunk)
        if len(body) > limit:
            raise _MCPMessageTooLarge("MCP response body exceeded the byte limit")
    return bytes(body)


def _validate_jsonrpc_message(payload: Any):
    """Return a native JSONRPCMessage model and its normalized JSON object."""
    if not isinstance(payload, dict):
        raise ValueError("JACS MCP payload must be a JSON-RPC object")
    try:
        from mcp.types import JSONRPCMessage

        model = JSONRPCMessage.model_validate(payload)
        normalized = model.model_dump(
            by_alias=True,
            mode="json",
            exclude_none=True,
        )
    except Exception as exc:
        raise ValueError(f"JACS MCP payload was not valid JSON-RPC 2.0: {exc}") from exc
    if not isinstance(normalized, dict):
        raise ValueError("JACS MCP JSON-RPC normalization did not return an object")
    return model, normalized


def _session_message_payload(message: Any) -> Dict[str, Any]:
    """Extract and validate JSON-RPC from current and legacy MCP session shapes."""
    if hasattr(message, "message"):
        value = message.message
    elif hasattr(message, "root"):
        # Compatibility with earlier MCP RootModel-shaped test doubles.
        value = message.root
    else:
        raise ValueError("MCP transport yielded an unsupported session message shape")

    if hasattr(value, "model_dump"):
        value = value.model_dump(by_alias=True, mode="json", exclude_none=True)
    _model, normalized = _validate_jsonrpc_message(value)
    return normalized


def _replace_session_message_payload(message: Any, payload: Dict[str, Any]) -> None:
    """Install validated JSON-RPC without replacing it by a JACS document."""
    model, normalized = _validate_jsonrpc_message(payload)
    if hasattr(message, "message"):
        message.message = model
        return
    if hasattr(message, "root"):
        message.root = normalized
        return
    raise ValueError("MCP transport yielded an unsupported session message shape")


def _build_signed_jsonrpc_carrier(
    payload: Dict[str, Any],
    envelope: str,
) -> Dict[str, Any]:
    """Build the cross-language schema-valid signed JSON-RPC carrier."""
    _model, normalized = _validate_jsonrpc_message(payload)
    if normalized.get("method") == JACS_MCP_SIGNED_CARRIER_METHOD:
        raise ValueError("Nested JACS MCP signed carriers are not allowed")
    require_portable_v2_signed_raw(envelope, context="JACS MCP signer")

    carrier = {
        "jsonrpc": "2.0",
        "method": JACS_MCP_SIGNED_CARRIER_METHOD,
        "params": {
            "version": JACS_MCP_SIGNED_CARRIER_VERSION,
            "envelope": envelope,
        },
    }
    _carrier_model, normalized_carrier = _validate_jsonrpc_message(carrier)
    return normalized_carrier


def _unwrap_signed_jsonrpc_carrier(
    carrier: Dict[str, Any],
    verifier: Callable[[str], Any],
) -> Dict[str, Any]:
    """Verify a strict carrier and return only its authenticated JSON-RPC payload."""
    _model, normalized = _validate_jsonrpc_message(carrier)
    params = normalized.get("params")
    if (
        set(normalized) != _JACS_MCP_CARRIER_KEYS
        or normalized.get("jsonrpc") != "2.0"
        or normalized.get("method") != JACS_MCP_SIGNED_CARRIER_METHOD
        or not isinstance(params, dict)
        or set(params) != _JACS_MCP_CARRIER_PARAM_KEYS
        or params.get("version") != JACS_MCP_SIGNED_CARRIER_VERSION
        or not isinstance(params.get("envelope"), str)
        or not params["envelope"]
    ):
        raise ValueError("Malformed JACS MCP signed carrier")

    verified_payload = verifier(params["envelope"])
    if isinstance(verified_payload, str):
        try:
            verified_payload = json.loads(verified_payload)
        except json.JSONDecodeError as exc:
            raise ValueError("Verified JACS MCP payload was not valid JSON") from exc
    _verified_model, authenticated = _validate_jsonrpc_message(verified_payload)
    if authenticated.get("method") == JACS_MCP_SIGNED_CARRIER_METHOD:
        raise ValueError("Verified JACS MCP payload contained a nested carrier")
    return authenticated


def _unwrap_authenticated_jsonrpc(
    document: Dict[str, Any],
    verifier: Callable[[str], Any],
) -> Dict[str, Any]:
    """Accept the v1 carrier or a legacy raw signed document, never plaintext."""
    if document.get("method") == JACS_MCP_SIGNED_CARRIER_METHOD:
        return _unwrap_signed_jsonrpc_carrier(document, verifier)
    if not isinstance(document.get("jacsSignature"), dict):
        raise ValueError("Unsigned MCP JSON-RPC messages are not allowed")
    verified_payload = verifier(json.dumps(document))
    if isinstance(verified_payload, str):
        try:
            verified_payload = json.loads(verified_payload)
        except json.JSONDecodeError as exc:
            raise ValueError("Verified MCP payload was not valid JSON") from exc
    _model, authenticated = _validate_jsonrpc_message(verified_payload)
    if authenticated.get("method") == JACS_MCP_SIGNED_CARRIER_METHOD:
        raise ValueError("Verified MCP payload contained a nested carrier")
    return authenticated


def _sign_session_message(
    message: Any,
    signer: Callable[[Dict[str, Any]], str],
) -> Optional[str]:
    payload = _session_message_payload(message)
    envelope = signer(payload)
    _replace_session_message_payload(
        message, _build_signed_jsonrpc_carrier(payload, envelope)
    )
    return None


def _sign_session_message_with_request_ids(
    message: Any,
    signer: Callable[[Dict[str, Any]], str],
    request_ids: _RequestIdState,
    *,
    allow_unsigned_fallback: bool = False,
) -> Optional[str]:
    payload = _session_message_payload(message)
    wire_payload, wire_id = request_ids.prepare_outbound(payload)
    try:
        envelope = signer(wire_payload)
        _replace_session_message_payload(
            message,
            _build_signed_jsonrpc_carrier(wire_payload, envelope),
        )
    except Exception as exc:
        if allow_unsigned_fallback:
            _replace_session_message_payload(message, wire_payload)
            LOGGER.warning(
                "JACS signing failed; sending explicit unsigned fallback: %s",
                exc,
            )
            return wire_id
        request_ids.discard(wire_id)
        raise
    return wire_id


def _restore_unsigned_session_message(
    message: Any,
    request_ids: _RequestIdState,
) -> None:
    """Restore correlation for an explicitly allowed unsigned response."""
    payload = _session_message_payload(message)
    if payload.get("method") == JACS_MCP_SIGNED_CARRIER_METHOD:
        raise simple.VerificationError(
            "Malformed signed carrier cannot downgrade to unsigned fallback"
        )
    restored = request_ids.restore_inbound(payload)
    _replace_session_message_payload(message, restored)


def _verify_session_message(
    message: Any,
    verifier: Callable[[str], Any],
) -> None:
    carrier = _session_message_payload(message)
    authenticated = _unwrap_signed_jsonrpc_carrier(carrier, verifier)
    _replace_session_message_payload(message, authenticated)


def _verify_session_message_with_request_ids(
    message: Any,
    verifier: Callable[[str], Any],
    request_ids: _RequestIdState,
) -> None:
    carrier = _session_message_payload(message)
    authenticated = _unwrap_signed_jsonrpc_carrier(carrier, verifier)
    authenticated = request_ids.restore_inbound(authenticated)
    _replace_session_message_payload(message, authenticated)


def _split_sse_frame(buffer: bytes):
    candidates = []
    for separator in (b"\r\n\r\n", b"\n\n"):
        index = buffer.find(separator)
        if index >= 0:
            candidates.append((index, separator))
    if not candidates:
        return None
    index, separator = min(candidates, key=lambda item: item[0])
    return buffer[:index], separator, buffer[index + len(separator) :]


def _sign_sse_frame(
    frame: bytes,
    signer: Callable[[Dict[str, Any]], str],
) -> bytes:
    """Sign one MCP ``event: message`` frame while preserving SSE framing."""
    try:
        text = frame.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("MCP SSE event was not valid UTF-8") from exc
    lines = text.splitlines()
    event_name = None
    data_indexes = []
    data_lines = []
    for index, line in enumerate(lines):
        if line.startswith("event:"):
            event_name = line[6:].lstrip(" ")
        elif line.startswith("data:"):
            data_indexes.append(index)
            data_lines.append(line[5:].lstrip(" "))
    if event_name != "message":
        return frame
    if not data_lines:
        raise ValueError("MCP SSE message event omitted data")
    try:
        payload = json.loads("\n".join(data_lines))
    except json.JSONDecodeError as exc:
        raise ValueError("MCP SSE message data was not valid JSON") from exc
    envelope = signer(payload)
    carrier = _build_signed_jsonrpc_carrier(payload, envelope)
    replacement = "data: " + json.dumps(
        carrier,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    first_data_index = data_indexes[0]
    data_index_set = set(data_indexes)
    rewritten = [
        line for index, line in enumerate(lines) if index not in data_index_set
    ]
    rewritten.insert(first_data_index, replacement)
    return "\n".join(rewritten).encode("utf-8")


async def _signed_sse_body_iterator(
    body_iterator,
    signer: Callable[[Dict[str, Any]], str],
    *,
    allow_unsigned_fallback: bool,
):
    """Incrementally sign bounded SSE message events without buffering a stream."""
    buffer = b""
    async for chunk in body_iterator:
        if not isinstance(chunk, bytes):
            chunk = str(chunk).encode("utf-8")
        buffer += chunk
        while True:
            split = _split_sse_frame(buffer)
            if split is None:
                if len(buffer) > MAX_SIGNED_SSE_EVENT_BYTES:
                    raise ValueError(
                        "MCP SSE event exceeded the signed event byte limit"
                    )
                break
            frame, separator, buffer = split
            if len(frame) > MAX_SIGNED_SSE_EVENT_BYTES:
                raise ValueError("MCP SSE event exceeded the signed event byte limit")
            try:
                signed_frame = _sign_sse_frame(frame, signer)
            except Exception as exc:
                LOGGER.warning("JACS MCP SSE event signing failed: %s", exc)
                if not allow_unsigned_fallback:
                    raise
                signed_frame = frame
            yield signed_frame + separator
    if buffer:
        if buffer.strip():
            raise ValueError("MCP SSE stream ended with an incomplete event")
        yield buffer


# ---------------------------------------------------------------------------
# Class-based API (uses JacsAgent instances)
# ---------------------------------------------------------------------------


def JACSMCPClient(
    url,
    config_path="./jacs.config.json",
    strict=False,
    local_only: Optional[bool] = None,
    allow_unsigned_fallback: Optional[bool] = None,
    expected_peer_agent_id: Optional[str] = None,
    expected_peer_public_key_hash: Optional[str] = None,
    allowed_peer_agent_ids: Optional[Iterable[str]] = None,
    allow_any_verified_peer: Optional[bool] = None,
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
        expected_peer_agent_id: Pinned server agent ID.
        expected_peer_public_key_hash: Optional exact public-key-hash pin for
            the expected server agent.
        allowed_peer_agent_ids: Alternative allowlist of server agent IDs.
        allow_any_verified_peer: Dangerous proof-of-possession-only mode that
            accepts any cryptographically valid signer. Default False.
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

    allowed_peers = frozenset()
    allow_any_peer = False
    expected_peer_key_hash = None
    if agent_ready:
        allowed_peers, allow_any_peer, expected_peer_key_hash = _resolve_peer_policy(
            expected_peer_agent_id=expected_peer_agent_id,
            allowed_peer_agent_ids=allowed_peer_agent_ids,
            allow_any_verified_peer=allow_any_verified_peer,
            expected_peer_public_key_hash=expected_peer_public_key_hash,
            context="JACSMCPClient",
        )
    verify_peer = _peer_verifier(
        agent,
        allowed_peers,
        allow_any_peer,
        expected_peer_key_hash,
    )

    transport = SSETransport(url)

    @contextlib.asynccontextmanager
    async def patched_connect_session(**session_kwargs):
        request_ids = _RequestIdState()
        async with sse_client(
            transport.url, headers=transport.headers
        ) as transport_streams:
            original_read_stream, original_write_stream = transport_streams

            original_send = original_write_stream.send

            async def intercepted_send(message, **send_kwargs):
                wire_id = None
                if agent_ready:
                    try:
                        wire_id = _sign_session_message_with_request_ids(
                            message,
                            agent.sign_request,
                            request_ids,
                            allow_unsigned_fallback=allow_unsigned_fallback,
                        )
                    except Exception as e:
                        if not allow_unsigned_fallback:
                            raise simple.SigningError(
                                f"JACS signing failed and unsigned fallback is disabled: {e}"
                            ) from e
                        LOGGER.warning(
                            "JACS signing failed, falling back to unsigned message: %s",
                            e,
                        )
                try:
                    return await original_send(message, **send_kwargs)
                except Exception:
                    request_ids.discard(wire_id)
                    raise

            original_write_stream.send = intercepted_send

            original_receive = original_read_stream.receive

            async def intercepted_receive(**receive_kwargs):
                message = await original_receive(**receive_kwargs)
                if agent_ready:
                    try:
                        _verify_session_message_with_request_ids(
                            message,
                            verify_peer,
                            request_ids,
                        )
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
                        _restore_unsigned_session_message(message, request_ids)
                return message

            original_read_stream.receive = intercepted_receive

            async with ClientSession(
                original_read_stream, original_write_stream, **session_kwargs
            ) as session:
                try:
                    yield session
                finally:
                    request_ids.clear()

    transport.connect_session = patched_connect_session
    return Client(transport, **kwargs)


def _build_jacs_starlette_middleware(
    agent,
    agent_ready,
    local_only,
    allow_unsigned_fallback,
    allowed_peer_agent_ids=frozenset(),
    allow_any_verified_peer=False,
    max_message_bytes=DEFAULT_MAX_MCP_MESSAGE_BYTES,
):
    """Build a Starlette-compatible ASGI middleware class for JACS auth.

    Returns a middleware class suitable for use with
    ``starlette.middleware.Middleware`` or ``app.middleware("http")``.
    """
    try:
        from starlette.middleware.base import BaseHTTPMiddleware
    except ImportError:
        BaseHTTPMiddleware = None

    if BaseHTTPMiddleware is None:
        raise ImportError(
            "starlette is required for JACS MCP server middleware. "
            "Install with: pip install starlette"
        )

    verify_peer = _peer_verifier(
        agent,
        allowed_peer_agent_ids,
        allow_any_verified_peer,
    )

    class JACSAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request_host = getattr(getattr(request, "client", None), "host", "") or ""
            if local_only and not _is_loopback_host(request_host):
                if JSONResponse is not None:
                    return JSONResponse(
                        {
                            "error": "MCP local mode only: remote clients are not allowed"
                        },
                        status_code=403,
                    )
                raise simple.VerificationError(
                    "MCP local mode only: remote clients are not allowed"
                )

            if getattr(request, "method", "").upper() == "POST":
                try:
                    body = await _read_bounded_request_body(
                        request,
                        max_message_bytes,
                    )
                except _MCPMessageTooLarge:
                    LOGGER.warning(
                        "JACS MCP request rejected: body exceeded byte limit"
                    )
                    if JSONResponse is not None:
                        return JSONResponse(
                            {"error": "MCP request body exceeded the byte limit"},
                            status_code=413,
                        )
                    raise
                if not agent_ready:
                    if not allow_unsigned_fallback:
                        if JSONResponse is not None:
                            return JSONResponse(
                                {"error": "JACS authentication unavailable"},
                                status_code=503,
                            )
                        raise simple.AgentNotLoadedError(
                            "No agent loaded; refusing unauthenticated MCP POST"
                        )
                elif not body:
                    if not allow_unsigned_fallback:
                        if JSONResponse is not None:
                            return JSONResponse(
                                {"error": "JACS verification failed: empty MCP POST"},
                                status_code=401,
                            )
                        raise simple.VerificationError("Empty MCP POST is not signed")
                else:
                    try:
                        data = json.loads(body)
                        if not isinstance(data, dict):
                            raise ValueError("MCP POST body must be a JSON object")
                        payload = _unwrap_authenticated_jsonrpc(
                            data,
                            verify_peer,
                        )
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

            content_type = response.headers.get("content-type", "")
            if "text/event-stream" in content_type and agent_ready:
                if StreamingResponse is None:
                    raise RuntimeError(
                        "Starlette StreamingResponse is required for signed MCP SSE"
                    )
                headers = dict(response.headers)
                headers.pop("content-length", None)
                return StreamingResponse(
                    _signed_sse_body_iterator(
                        response.body_iterator,
                        agent.sign_request,
                        allow_unsigned_fallback=allow_unsigned_fallback,
                    ),
                    status_code=response.status_code,
                    headers=headers,
                    media_type=response.media_type,
                )

            if "application/json" in content_type:
                if not agent_ready:
                    # This state is reachable only with the explicit unsigned
                    # fallback. Do not consume the downstream iterator merely
                    # to return an exhausted response.
                    return response
                try:
                    body = await _read_bounded_response_body(
                        response.body_iterator,
                        max_message_bytes,
                    )
                except _MCPMessageTooLarge:
                    LOGGER.warning(
                        "JACS MCP response rejected: body exceeded byte limit"
                    )
                    if JSONResponse is not None:
                        return JSONResponse(
                            {"error": "MCP response body exceeded the byte limit"},
                            status_code=500,
                        )
                    raise

                try:
                    data = json.loads(body.decode())
                    signed_json = agent.sign_request(data)
                    carrier = _build_signed_jsonrpc_carrier(data, signed_json)
                    carrier_bytes = json.dumps(carrier).encode()
                    headers = dict(response.headers)
                    headers.pop("content-length", None)
                    return Response(
                        content=carrier_bytes,
                        status_code=response.status_code,
                        headers=headers,
                        media_type=response.media_type,
                    )
                except Exception as e:
                    if allow_unsigned_fallback:
                        LOGGER.warning("JACS signing failed: %s", e)
                        headers = dict(response.headers)
                        headers.pop("content-length", None)
                        return Response(
                            content=body,
                            status_code=response.status_code,
                            headers=headers,
                            media_type=response.media_type,
                        )
                    if JSONResponse is not None:
                        return JSONResponse(
                            {"error": f"JACS signing failed: {e}"},
                            status_code=500,
                        )
                    raise

            return response

    return JACSAuthMiddleware


def JACSMCPServer(
    mcp_server,
    config_path="./jacs.config.json",
    strict=False,
    local_only: Optional[bool] = None,
    allow_unsigned_fallback: Optional[bool] = None,
    allowed_peer_agent_ids: Optional[Iterable[str]] = None,
    allow_any_verified_peer: Optional[bool] = None,
    max_message_bytes: Optional[int] = None,
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
        allowed_peer_agent_ids: Allowed client signer IDs.
        allow_any_verified_peer: Dangerous proof-of-possession-only mode.
        max_message_bytes: Hard cap for JSON request and response bodies.

    The returned server can be deployed via::

        app = mcp_server.http_app()
        uvicorn.run(app, host="localhost", port=8000)
    """
    if JacsAgent is None:
        raise ImportError("jacs native module is required for JACSMCPServer")

    strict = _resolve_strict(strict)
    local_only = _resolve_local_only(local_only)
    allow_unsigned_fallback = _resolve_allow_unsigned_fallback(allow_unsigned_fallback)
    max_message_bytes = _resolve_max_message_bytes(max_message_bytes)
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

    allowed_peers = frozenset()
    allow_any_peer = False
    if agent_ready:
        allowed_peers, allow_any_peer, _expected_peer_key_hash = _resolve_peer_policy(
            allowed_peer_agent_ids=allowed_peer_agent_ids,
            allow_any_verified_peer=allow_any_verified_peer,
            context="JACSMCPServer",
            require_policy=False,
        )

    # Build the Starlette middleware class for JACS auth
    middleware_cls = _build_jacs_starlette_middleware(
        agent,
        agent_ready,
        local_only,
        allow_unsigned_fallback,
        allowed_peers,
        allow_any_peer,
        max_message_bytes,
    )

    # Patch http_app to inject JACS middleware (fastmcp 3.x)
    if hasattr(mcp_server, "http_app"):
        original_http_app = mcp_server.http_app

        def patched_http_app(*args, **kwargs):
            # Merge JACS middleware with any user-supplied middleware
            from starlette.middleware import Middleware

            jacs_mw = Middleware(middleware_cls)
            user_middleware = list(kwargs.pop("middleware", None) or [])
            user_middleware.insert(0, jacs_mw)
            kwargs["middleware"] = user_middleware
            kwargs.setdefault("transport", "sse")
            return original_http_app(*args, **kwargs)

        mcp_server.http_app = patched_http_app

    if hasattr(mcp_server, "run"):
        original_run = mcp_server.run

        def patched_run(transport=None, *args, **kwargs):
            return original_run(
                _secure_server_transport(transport),
                *args,
                **kwargs,
            )

        mcp_server.run = patched_run

    if hasattr(mcp_server, "run_async"):
        original_run_async = mcp_server.run_async

        async def patched_run_async(transport=None, *args, **kwargs):
            return await original_run_async(
                _secure_server_transport(transport),
                *args,
                **kwargs,
            )

        mcp_server.run_async = patched_run_async

    # Store middleware class on server for direct access
    mcp_server._jacs_middleware_cls = middleware_cls

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
        raise simple.AgentNotLoadedError("No agent loaded. Call jacs.load() first.")

    _model, normalized = _validate_jsonrpc_message(message)
    agent = simple._get_agent()
    signed_json = agent.sign_request(normalized)
    # Apply the same portable-v2 completeness policy before the value enters a
    # transport carrier. The returned string remains the cross-language wire
    # envelope rather than a Python-specific wrapper.
    _build_signed_jsonrpc_carrier(normalized, signed_json)
    return signed_json


def verify_mcp_message(
    signed_json: str,
    *,
    expected_peer_agent_id: Optional[str] = None,
    expected_peer_public_key_hash: Optional[str] = None,
    allowed_peer_agent_ids: Optional[Iterable[str]] = None,
    allow_any_verified_peer: Optional[bool] = None,
) -> Dict[str, Any]:
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
        raise simple.AgentNotLoadedError("No agent loaded. Call jacs.load() first.")

    agent = simple._get_agent()
    try:
        allowed_peers, allow_any_peer, expected_peer_key_hash = _resolve_peer_policy(
            expected_peer_agent_id=expected_peer_agent_id,
            allowed_peer_agent_ids=allowed_peer_agent_ids,
            allow_any_verified_peer=allow_any_verified_peer,
            expected_peer_public_key_hash=expected_peer_public_key_hash,
            context="verify_mcp_message",
        )
        payload = _peer_verifier(
            agent,
            allowed_peers,
            allow_any_peer,
            expected_peer_key_hash,
        )(signed_json)
        _model, normalized = _validate_jsonrpc_message(payload)
        if normalized.get("method") == JACS_MCP_SIGNED_CARRIER_METHOD:
            raise ValueError("Verified MCP payload contained a nested carrier")
        return normalized
    except Exception as exc:
        raise simple.VerificationError(
            f"MCP message verification failed: {exc}"
        ) from exc


def jacs_tool(
    func: Optional[Callable] = None,
    *,
    allow_unsigned_fallback: bool = False,
) -> Callable:
    """Decorator to add JACS signing to an MCP tool.

    Use this decorator on MCP tool functions to automatically
    sign the response.

    Example:
        @mcp.tool()
        @jacs_tool
        def my_tool(arg: str) -> str:
            return f"Result: {arg}"

    Unsigned output is rejected by default. The
    ``allow_unsigned_fallback=True`` option is a dangerous compatibility
    escape hatch for deployments that intentionally accept unsigned results.
    """
    allow_unsigned_fallback = allow_unsigned_fallback is True

    def decorator(wrapped_func: Callable) -> Callable:
        @wraps(wrapped_func)
        async def wrapper(*args, **kwargs):
            result = wrapped_func(*args, **kwargs)

            if hasattr(result, "__await__"):
                result = await result

            if not simple.is_loaded():
                if allow_unsigned_fallback:
                    LOGGER.warning(
                        "JACS tool agent is not loaded; returning unsigned output"
                    )
                    return result
                raise simple.AgentNotLoadedError(
                    "No agent loaded; refusing to return unsigned MCP tool output"
                )

            try:
                signed = simple.sign_message(json.dumps(result))
                raw = require_portable_v2_signed_raw(
                    signed.raw_json,
                    context="jacs_tool",
                )
                return json.loads(raw)
            except Exception as exc:
                LOGGER.warning("JACS MCP tool output signing failed: %s", exc)
                if not allow_unsigned_fallback:
                    raise
                return result

        return wrapper

    if func is not None:
        return decorator(func)
    return decorator


def jacs_middleware(
    *,
    local_only: Optional[bool] = None,
    allow_unsigned_fallback: Optional[bool] = None,
    allowed_peer_agent_ids: Optional[Iterable[str]] = None,
    allow_any_verified_peer: Optional[bool] = None,
    max_message_bytes: Optional[int] = None,
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
    max_message_bytes = _resolve_max_message_bytes(max_message_bytes)
    allowed_peers, allow_any_peer, _expected_peer_key_hash = _resolve_peer_policy(
        allowed_peer_agent_ids=allowed_peer_agent_ids,
        allow_any_verified_peer=allow_any_verified_peer,
        context="jacs_middleware",
        require_policy=False,
    )

    def verify_peer(signed_json: str):
        agent = simple._get_agent()
        return _peer_verifier(agent, allowed_peers, allow_any_peer)(signed_json)

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

        if not simple.is_loaded() and not allow_unsigned_fallback:
            LOGGER.warning(
                "JACS MCP request rejected because no signing agent is loaded"
            )
            if JSONResponse is not None:
                return JSONResponse(
                    {"error": "JACS authentication unavailable"},
                    status_code=503,
                )
            raise simple.AgentNotLoadedError(
                "No agent loaded; refusing to process unauthenticated MCP request"
            )

        # Every MCP POST is an authentication boundary. GET performs the SSE
        # handshake and DELETE performs protocol cleanup, so neither is wrapped.
        request_method = getattr(request, "method", "").upper()
        if request_method == "POST":
            try:
                body = await _read_bounded_request_body(
                    request,
                    max_message_bytes,
                )
            except _MCPMessageTooLarge:
                LOGGER.warning("JACS MCP request rejected: body exceeded byte limit")
                if JSONResponse is not None:
                    return JSONResponse(
                        {"error": "MCP request body exceeded the byte limit"},
                        status_code=413,
                    )
                raise
            if not body and not allow_unsigned_fallback:
                if JSONResponse is not None:
                    return JSONResponse(
                        {"error": "JACS verification failed: empty MCP POST"},
                        status_code=401,
                    )
                raise simple.VerificationError("Empty MCP POST is not signed")
            try:
                data = json.loads(body)
                if not isinstance(data, dict):
                    raise ValueError("MCP POST body must be a JSON object")
                payload = _unwrap_authenticated_jsonrpc(
                    data,
                    verify_peer,
                )
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

        # Sign outgoing JSON responses
        if Response is not None:
            content_type = response.headers.get("content-type", "")
            if "text/event-stream" in content_type and not simple.is_loaded():
                LOGGER.warning(
                    "JACS SSE signing unavailable because no agent is loaded"
                )
                if allow_unsigned_fallback:
                    return response
                if JSONResponse is not None:
                    return JSONResponse(
                        {"error": "JACS SSE signing unavailable"},
                        status_code=503,
                    )
                raise simple.AgentNotLoadedError(
                    "No agent loaded; refusing to return unsigned MCP SSE"
                )
            if "text/event-stream" in content_type:
                if StreamingResponse is None:
                    raise RuntimeError(
                        "Starlette StreamingResponse is required for signed MCP SSE"
                    )
                headers = dict(response.headers)
                headers.pop("content-length", None)
                return StreamingResponse(
                    _signed_sse_body_iterator(
                        response.body_iterator,
                        sign_mcp_message,
                        allow_unsigned_fallback=allow_unsigned_fallback,
                    ),
                    status_code=response.status_code,
                    headers=headers,
                    media_type=response.media_type,
                )
            if "application/json" in content_type:
                if not simple.is_loaded():
                    LOGGER.warning(
                        "JACS response signing unavailable because no agent is loaded"
                    )
                    if allow_unsigned_fallback:
                        return response
                    if JSONResponse is not None:
                        return JSONResponse(
                            {"error": "JACS response signing unavailable"},
                            status_code=503,
                        )
                    raise simple.AgentNotLoadedError(
                        "No agent loaded; refusing to return unsigned MCP response"
                    )

                try:
                    resp_body = await _read_bounded_response_body(
                        response.body_iterator,
                        max_message_bytes,
                    )
                except _MCPMessageTooLarge:
                    LOGGER.warning(
                        "JACS MCP response rejected: body exceeded byte limit"
                    )
                    if JSONResponse is not None:
                        return JSONResponse(
                            {"error": "MCP response body exceeded the byte limit"},
                            status_code=500,
                        )
                    raise

                try:
                    data = json.loads(resp_body.decode())
                    signed = sign_mcp_message(data)
                    carrier = _build_signed_jsonrpc_carrier(data, signed)
                    headers = dict(response.headers)
                    headers.pop("content-length", None)
                    return Response(
                        content=json.dumps(carrier).encode(),
                        status_code=response.status_code,
                        headers=headers,
                        media_type=response.media_type,
                    )
                except Exception as e:
                    LOGGER.warning("JACS response signing failed: %s", e)
                    if allow_unsigned_fallback:
                        headers = dict(response.headers)
                        headers.pop("content-length", None)
                        return Response(
                            content=resp_body,
                            status_code=response.status_code,
                            headers=headers,
                            media_type=response.media_type,
                        )
                    elif JSONResponse is not None:
                        return JSONResponse(
                            {"error": "JACS response signing failed"},
                            status_code=500,
                        )
                    else:
                        raise

        return response

    return middleware


class JacsSSETransport(_JacsSSETransportBase):
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
        expected_peer_agent_id: Optional[str] = None,
        expected_peer_public_key_hash: Optional[str] = None,
        allowed_peer_agent_ids: Optional[Iterable[str]] = None,
        allow_any_verified_peer: Optional[bool] = None,
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
        (
            self._allowed_peer_agent_ids,
            self._allow_any_verified_peer,
            self._expected_peer_public_key_hash,
        ) = _resolve_peer_policy(
            expected_peer_agent_id=expected_peer_agent_id,
            allowed_peer_agent_ids=allowed_peer_agent_ids,
            allow_any_verified_peer=allow_any_verified_peer,
            expected_peer_public_key_hash=expected_peer_public_key_hash,
            context="JacsSSETransport",
            require_policy=False,
        )
        super().__init__(url, headers=headers)

    @contextlib.asynccontextmanager
    async def connect_session(self, **session_kwargs):
        """Connect with JACS signing/verification interceptors."""
        if sse_client is None or ClientSession is None:
            raise ImportError(
                "mcp is required for JacsSSETransport. Install with: pip install mcp"
            )

        agent_ready = simple.is_loaded()
        if not agent_ready:
            if not self._allow_unsigned_fallback:
                raise simple.AgentNotLoadedError(
                    "No agent loaded; refusing to open unsigned MCP transport"
                )
            LOGGER.warning("JACS agent is not loaded; MCP transport will be unsigned")
        elif not self._allowed_peer_agent_ids and not self._allow_any_verified_peer:
            raise simple.ConfigError(
                "JacsSSETransport: authenticated MCP requires an explicit peer "
                "agent ID; allow_any_verified_peer=True is dangerous compatibility mode"
            )

        request_ids = _RequestIdState()
        verify_peer = None
        if agent_ready:
            verify_peer = _peer_verifier(
                simple._get_agent(),
                self._allowed_peer_agent_ids,
                self._allow_any_verified_peer,
                self._expected_peer_public_key_hash,
            )

        async with sse_client(self.url, headers=self.headers) as transport_streams:
            original_read_stream, original_write_stream = transport_streams

            original_send = original_write_stream.send

            async def intercepted_send(message, **send_kwargs):
                wire_id = None
                if agent_ready:
                    try:
                        wire_id = _sign_session_message_with_request_ids(
                            message,
                            sign_mcp_message,
                            request_ids,
                            allow_unsigned_fallback=self._allow_unsigned_fallback,
                        )
                    except Exception as e:
                        LOGGER.warning(
                            "JACS signing on send failed: %s",
                            e,
                        )
                        if not self._allow_unsigned_fallback:
                            raise simple.SigningError(
                                "JACS signing failed and unsigned fallback is disabled: "
                                f"{e}"
                            ) from e
                try:
                    return await original_send(message, **send_kwargs)
                except Exception:
                    request_ids.discard(wire_id)
                    raise

            original_write_stream.send = intercepted_send

            original_receive = original_read_stream.receive

            async def intercepted_receive(**receive_kwargs):
                message = await original_receive(**receive_kwargs)
                if agent_ready:
                    try:
                        _verify_session_message_with_request_ids(
                            message,
                            verify_peer,
                            request_ids,
                        )
                    except Exception as e:
                        if self._allow_unsigned_fallback:
                            LOGGER.warning("JACS verification on receive failed: %s", e)
                            _restore_unsigned_session_message(message, request_ids)
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
                try:
                    yield session
                finally:
                    request_ids.clear()


def create_jacs_mcp_server(
    name: str,
    config_path: Optional[str] = None,
    *,
    local_only: Optional[bool] = None,
    allow_unsigned_fallback: Optional[bool] = None,
    allowed_peer_agent_ids: Optional[Iterable[str]] = None,
    allow_any_verified_peer: Optional[bool] = None,
    max_message_bytes: Optional[int] = None,
):
    """Create a FastMCP server with JACS authentication built-in.

    This is the simplest way to create an authenticated MCP server.
    It loads the JACS agent from ``config_path``, creates a FastMCP
    server, and wires up ``jacs_middleware()`` so every JSON response
    is signed and every POST must be signed by an explicitly allowed peer.

    Args:
        name: Server name
        config_path: Path to JACS config (default: ./jacs.config.json)

    Returns:
        Configured FastMCP server instance

    Example:
        mcp = create_jacs_mcp_server(
            "My Server",
            allowed_peer_agent_ids=["EXPECTED_CLIENT_AGENT_ID"],
        )

        @mcp.tool()
        def hello(name: str) -> str:
            return f"Hello, {name}!"

        mcp.run(transport="sse")
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

    # Wire JACS middleware into http_app (fastmcp 3.x)
    middleware_fn = jacs_middleware(
        local_only=local_only,
        allow_unsigned_fallback=allow_unsigned_fallback,
        allowed_peer_agent_ids=allowed_peer_agent_ids,
        allow_any_verified_peer=allow_any_verified_peer,
        max_message_bytes=max_message_bytes,
    )

    if hasattr(mcp_server, "http_app"):
        original_http_app = mcp_server.http_app

        def patched_http_app(*args, **kwargs):
            from starlette.middleware.base import BaseHTTPMiddleware

            class _JacsSimpleMW(BaseHTTPMiddleware):
                async def dispatch(self, request, call_next):
                    return await middleware_fn(request, call_next)

            from starlette.middleware import Middleware

            jacs_mw = Middleware(_JacsSimpleMW)
            user_middleware = list(kwargs.pop("middleware", None) or [])
            user_middleware.insert(0, jacs_mw)
            kwargs["middleware"] = user_middleware
            kwargs.setdefault("transport", "sse")
            return original_http_app(*args, **kwargs)

        mcp_server.http_app = patched_http_app

    original_run = mcp_server.run

    def patched_run(transport=None, *args, **kwargs):
        return original_run(
            _secure_server_transport(transport),
            *args,
            **kwargs,
        )

    mcp_server.run = patched_run

    original_run_async = mcp_server.run_async

    async def patched_run_async(transport=None, *args, **kwargs):
        return await original_run_async(
            _secure_server_transport(transport),
            *args,
            **kwargs,
        )

    mcp_server.run_async = patched_run_async

    return mcp_server


async def jacs_call(
    server_url: str,
    method: str,
    local_only: Optional[bool] = None,
    expected_peer_agent_id: Optional[str] = None,
    expected_peer_public_key_hash: Optional[str] = None,
    allow_any_verified_peer: Optional[bool] = None,
    **params: Any,
) -> Any:
    """Make an authenticated MCP call to a server.

    This is a convenience function for making one-off MCP calls
    with JACS authentication.

    Args:
        server_url: URL of the MCP server
        method: MCP method to call
        local_only: Reserved for compatibility. Local-only is always enforced.
        expected_peer_agent_id: Pinned server signer identity.
        expected_peer_public_key_hash: Optional exact server key-hash pin.
        allow_any_verified_peer: Dangerous proof-of-possession-only mode.
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
        raise simple.AgentNotLoadedError("No agent loaded. Call jacs.load() first.")

    if Client is None or SSETransport is None:
        raise ImportError(
            "fastmcp is required for MCP client support. "
            "Install with: pip install fastmcp"
        )

    local_only = _resolve_local_only(local_only)
    _enforce_local_url(server_url, "jacs_call", local_only)

    transport = JacsSSETransport(
        server_url,
        local_only=local_only,
        expected_peer_agent_id=expected_peer_agent_id,
        expected_peer_public_key_hash=expected_peer_public_key_hash,
        allow_any_verified_peer=allow_any_verified_peer,
    )
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
