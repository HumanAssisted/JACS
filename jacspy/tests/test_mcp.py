"""Tests for the JACS MCP integration wrappers."""

import asyncio
import contextlib
import pytest
from unittest.mock import Mock, AsyncMock
import json
from types import SimpleNamespace


def _portable_test_envelope(payload, label="test"):
    return json.dumps(
        {
            "jacsId": f"document-{label}",
            "jacsVersion": f"version-{label}",
            "jacsDocument": {"content": payload},
            "jacsSignature": {
                "signature": f"signature-{label}",
                "agentID": f"agent-{label}",
                "agentVersion": f"agent-version-{label}",
                "publicKeyHash": f"key-hash-{label}",
                "date": "2026-07-10T00:00:00Z",
                "signatureContentVersion": "jacs-signature-v2",
            },
        }
    )


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

        # Create a mock FastMCP server with http_app (fastmcp 3.x)
        mock_server = Mock()
        mock_server.http_app = Mock(return_value=Mock())

        # Wrap it
        wrapped_server = JACSMCPServer(
            mock_server,
            allow_unsigned_fallback=True,
        )

        # The wrapper should return the same object (modified in place)
        assert wrapped_server is mock_server

        # The http_app should have been replaced and middleware class stored
        assert mock_server.http_app is not None
        assert hasattr(mock_server, "_jacs_middleware_cls")

    def test_wrapper_preserves_server_attributes(self):
        """Test that the wrapper preserves other server attributes."""
        from jacs.mcp import JACSMCPServer

        mock_server = Mock()
        mock_server.http_app = Mock(return_value=Mock())
        mock_server.some_attribute = "test_value"
        mock_server.some_method = Mock(return_value="method_result")

        wrapped_server = JACSMCPServer(
            mock_server,
            allow_unsigned_fallback=True,
        )

        # Other attributes should be preserved
        assert wrapped_server.some_attribute == "test_value"
        assert wrapped_server.some_method() == "method_result"

    def test_server_entrypoints_default_to_authenticated_http_and_reject_stdio(self):
        from jacs import mcp

        original_http_app = Mock(return_value=Mock())
        original_run = Mock(return_value=None)
        mock_server = SimpleNamespace(
            http_app=original_http_app,
            run=original_run,
        )
        wrapped = mcp.JACSMCPServer(
            mock_server,
            allow_unsigned_fallback=True,
        )

        wrapped.http_app()
        assert original_http_app.call_args.kwargs["transport"] == "sse"
        wrapped.run()
        original_run.assert_called_once_with("sse")
        with pytest.raises(mcp.simple.ConfigError, match="stdio bypasses"):
            wrapped.run("stdio")

    def test_simple_server_entrypoints_reject_stdio(self, monkeypatch):
        import fastmcp as fastmcp_module
        from jacs import mcp

        original_run = Mock(return_value=None)
        fake_server = SimpleNamespace(
            http_app=Mock(return_value=Mock()),
            run=original_run,
            run_async=AsyncMock(return_value=None),
        )
        monkeypatch.setattr(fastmcp_module, "FastMCP", lambda _name: fake_server)
        monkeypatch.setattr(mcp.simple, "load", Mock())

        wrapped = mcp.create_jacs_mcp_server(
            "test",
            allowed_peer_agent_ids=["client-agent"],
        )
        wrapped.run()
        original_run.assert_called_once_with("sse")
        with pytest.raises(mcp.simple.ConfigError, match="stdio bypasses"):
            wrapped.run("stdio")


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


class TestSignedJsonRpcCarrier:
    """The transport carrier remains MCP-schema-valid before verification."""

    def test_current_session_message_shape_round_trips_authenticated_jsonrpc(self):
        from jacs import mcp
        from mcp.shared.message import SessionMessage
        from mcp.types import JSONRPCMessage

        original = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "example", "arguments": {}},
        }
        envelope = _portable_test_envelope(original)
        session_message = SessionMessage(JSONRPCMessage.model_validate(original))

        mcp._sign_session_message(session_message, lambda payload: envelope)

        carrier = session_message.message.model_dump(
            by_alias=True,
            mode="json",
            exclude_none=True,
        )
        assert carrier == {
            "jsonrpc": "2.0",
            "method": mcp.JACS_MCP_SIGNED_CARRIER_METHOD,
            "params": {
                "version": mcp.JACS_MCP_SIGNED_CARRIER_VERSION,
                "envelope": envelope,
            },
        }

        mcp._verify_session_message(
            session_message,
            lambda received: original if received == envelope else None,
        )
        assert (
            session_message.message.model_dump(
                by_alias=True,
                mode="json",
                exclude_none=True,
            )
            == original
        )

    @pytest.mark.parametrize(
        "field_path",
        [
            ("jacsId",),
            ("jacsVersion",),
            ("jacsSignature", "signature"),
            ("jacsSignature", "agentID"),
            ("jacsSignature", "agentVersion"),
            ("jacsSignature", "publicKeyHash"),
            ("jacsSignature", "date"),
            ("jacsSignature", "signatureContentVersion"),
        ],
    )
    def test_carrier_builder_requires_complete_portable_v2_envelope(self, field_path):
        from jacs import mcp

        payload = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}
        document = json.loads(_portable_test_envelope(payload))
        target = document
        for component in field_path[:-1]:
            target = target[component]
        target.pop(field_path[-1])

        with pytest.raises(ValueError, match="incomplete portable v2"):
            mcp._build_signed_jsonrpc_carrier(payload, json.dumps(document))

    @pytest.mark.parametrize(
        "envelope",
        [
            "",
            '{"result":"plain"}',
            json.dumps(
                {
                    **json.loads(_portable_test_envelope({})),
                    "jacsSignature": {
                        **json.loads(_portable_test_envelope({}))["jacsSignature"],
                        "signatureContentVersion": "jacs-signature-v1",
                    },
                }
            ),
            json.dumps(
                {
                    **json.loads(_portable_test_envelope({})),
                    "jacsSignature": {
                        **json.loads(_portable_test_envelope({}))["jacsSignature"],
                        "publicKeyHash": "",
                    },
                }
            ),
        ],
    )
    def test_carrier_rejects_empty_plain_legacy_and_incomplete_outputs(self, envelope):
        from jacs import mcp

        with pytest.raises(ValueError, match="portable v2"):
            mcp._build_signed_jsonrpc_carrier(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                envelope,
            )

    @pytest.mark.parametrize(
        "mutation",
        [
            lambda carrier: carrier.update({"extra": True}),
            lambda carrier: carrier["params"].update({"extra": True}),
            lambda carrier: carrier["params"].update({"version": 2}),
            lambda carrier: carrier["params"].update({"envelope": 7}),
        ],
    )
    def test_malformed_carrier_fails_closed(self, mutation):
        from jacs import mcp

        carrier = {
            "jsonrpc": "2.0",
            "method": mcp.JACS_MCP_SIGNED_CARRIER_METHOD,
            "params": {
                "version": mcp.JACS_MCP_SIGNED_CARRIER_VERSION,
                "envelope": '{"jacsSignature":{}}',
            },
        }
        mutation(carrier)

        with pytest.raises(ValueError, match="Malformed JACS MCP signed carrier"):
            mcp._unwrap_signed_jsonrpc_carrier(carrier, lambda _envelope: {})

    def test_unsigned_jsonrpc_cannot_enter_verified_transport(self):
        from jacs import mcp

        unsigned = {"jsonrpc": "2.0", "id": 1, "result": {}}

        with pytest.raises(ValueError, match="Malformed JACS MCP signed carrier"):
            mcp._unwrap_signed_jsonrpc_carrier(unsigned, lambda _envelope: unsigned)

    def test_verified_non_jsonrpc_payload_fails_closed(self):
        from jacs import mcp

        carrier = {
            "jsonrpc": "2.0",
            "method": mcp.JACS_MCP_SIGNED_CARRIER_METHOD,
            "params": {
                "version": mcp.JACS_MCP_SIGNED_CARRIER_VERSION,
                "envelope": '{"jacsSignature":{}}',
            },
        }

        with pytest.raises(ValueError, match="not valid JSON-RPC"):
            mcp._unwrap_signed_jsonrpc_carrier(
                carrier,
                lambda _envelope: {"attacker": "not jsonrpc"},
            )

    def test_peer_verification_binds_agent_and_optional_key_hash(self):
        from jacs import mcp

        payload = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        intended = _portable_test_envelope(payload, "intended")
        wrong = _portable_test_envelope(payload, "wrong")

        class ValidSignerResolver:
            def verify_response_with_agent_id(self, envelope):
                document = json.loads(envelope)
                signature = document["jacsSignature"]
                return signature["agentID"], document["jacsDocument"]["content"]

        verifier = mcp._peer_verifier(
            ValidSignerResolver(),
            frozenset({"agent-intended"}),
            False,
            "key-hash-intended",
        )

        assert verifier(intended) == payload
        with pytest.raises(mcp.simple.VerificationError, match="Unexpected MCP peer"):
            verifier(wrong)

        key_mismatch = json.loads(intended)
        key_mismatch["jacsSignature"]["publicKeyHash"] = "other-key"
        with pytest.raises(mcp.simple.VerificationError, match="public-key hash"):
            verifier(json.dumps(key_mismatch))

    def test_peer_verifier_rejects_native_metadata_identity_disagreement(self):
        from jacs import mcp

        payload = {"jsonrpc": "2.0", "id": 1, "result": {}}
        envelope = _portable_test_envelope(payload, "metadata")
        agent = SimpleNamespace(
            verify_response_with_agent_id=lambda _envelope: (
                "different-native-agent",
                payload,
            )
        )

        with pytest.raises(mcp.simple.VerificationError, match="signed metadata"):
            mcp._peer_verifier(
                agent,
                frozenset({"different-native-agent"}),
                False,
            )(envelope)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {
                "expected_peer_agent_id": "agent-a",
                "allowed_peer_agent_ids": ["agent-b"],
            },
            {
                "expected_peer_agent_id": "agent-a",
                "allow_any_verified_peer": True,
            },
            {"expected_peer_agent_id": " agent-a"},
            {"allow_any_verified_peer": "true"},
            {"expected_peer_public_key_hash": "hash-only"},
        ],
    )
    def test_peer_policy_rejects_ambiguous_or_nonliteral_configuration(self, kwargs):
        from jacs import mcp

        with pytest.raises(mcp.simple.ConfigError):
            mcp._resolve_peer_policy(context="test", **kwargs)

    def test_request_ids_are_session_unique_and_block_response_transplant(self):
        from jacs import mcp
        from mcp.shared.message import SessionMessage
        from mcp.types import JSONRPCMessage

        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        state_a = mcp._RequestIdState()
        state_b = mcp._RequestIdState()

        def sign(payload):
            return _portable_test_envelope(payload, str(payload["id"]))

        message_a = SessionMessage(JSONRPCMessage.model_validate(request))
        message_b = SessionMessage(JSONRPCMessage.model_validate(request))
        wire_a = mcp._sign_session_message_with_request_ids(
            message_a,
            sign,
            state_a,
        )
        wire_b = mcp._sign_session_message_with_request_ids(
            message_b,
            sign,
            state_b,
        )

        assert wire_a != wire_b
        response_a = {"jsonrpc": "2.0", "id": wire_a, "result": {"from": "a"}}
        carrier_a = mcp._build_signed_jsonrpc_carrier(
            response_a,
            _portable_test_envelope(response_a, "response-a"),
        )
        transplanted = SessionMessage(JSONRPCMessage.model_validate(carrier_a))

        with pytest.raises(mcp.simple.VerificationError, match="pending request"):
            mcp._verify_session_message_with_request_ids(
                transplanted,
                lambda _envelope: response_a,
                state_b,
            )

        response_b = {"jsonrpc": "2.0", "id": wire_b, "result": {"from": "b"}}
        carrier_b = mcp._build_signed_jsonrpc_carrier(
            response_b,
            _portable_test_envelope(response_b, "response-b"),
        )
        correct = SessionMessage(JSONRPCMessage.model_validate(carrier_b))
        mcp._verify_session_message_with_request_ids(
            correct,
            lambda _envelope: response_b,
            state_b,
        )
        assert (
            correct.message.model_dump(
                by_alias=True,
                mode="json",
                exclude_none=True,
            )["id"]
            == 1
        )

    def test_unsigned_fallback_keeps_randomized_response_correlation(self):
        from jacs import mcp
        from mcp.shared.message import SessionMessage
        from mcp.types import JSONRPCMessage

        state = mcp._RequestIdState()
        request = SessionMessage(
            JSONRPCMessage.model_validate(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            )
        )
        wire_id = mcp._sign_session_message_with_request_ids(
            request,
            lambda _payload: (_ for _ in ()).throw(RuntimeError("no signer")),
            state,
            allow_unsigned_fallback=True,
        )
        assert (
            request.message.model_dump(
                by_alias=True,
                mode="json",
                exclude_none=True,
            )["id"]
            == wire_id
        )

        response = SessionMessage(
            JSONRPCMessage.model_validate(
                {"jsonrpc": "2.0", "id": wire_id, "result": {"ok": True}}
            )
        )
        mcp._restore_unsigned_session_message(response, state)
        assert (
            response.message.model_dump(
                by_alias=True,
                mode="json",
                exclude_none=True,
            )["id"]
            == 1
        )

    def test_sse_message_event_is_incrementally_rewritten_as_carrier(self):
        from jacs import mcp

        original = {"jsonrpc": "2.0", "id": 9, "result": {"ok": True}}
        envelope = _portable_test_envelope(original)
        wire = (
            b"event: endpoint\ndata: /messages/?session_id=1\n\n"
            + b"event: message\ndata: "
            + json.dumps(original).encode()
            + b"\n\n"
        )

        async def chunks():
            yield wire[:17]
            yield wire[17:61]
            yield wire[61:]

        async def collect():
            return b"".join(
                [
                    chunk
                    async for chunk in mcp._signed_sse_body_iterator(
                        chunks(),
                        lambda _payload: envelope,
                        allow_unsigned_fallback=False,
                    )
                ]
            )

        rewritten = asyncio.run(collect())
        assert b"event: endpoint\ndata: /messages/?session_id=1\n\n" in rewritten
        message_frame = rewritten.split(b"event: message\ndata: ", 1)[1].split(
            b"\n\n", 1
        )[0]
        carrier = json.loads(message_frame)
        assert carrier["method"] == mcp.JACS_MCP_SIGNED_CARRIER_METHOD
        assert (
            mcp._unwrap_signed_jsonrpc_carrier(
                carrier,
                lambda received: original if received == envelope else None,
            )
            == original
        )

    def test_sse_event_size_is_bounded(self, monkeypatch):
        from jacs import mcp

        monkeypatch.setattr(mcp, "MAX_SIGNED_SSE_EVENT_BYTES", 8)

        async def chunks():
            yield b"event: message\ndata: {}"

        async def collect():
            return [
                chunk
                async for chunk in mcp._signed_sse_body_iterator(
                    chunks(),
                    lambda _payload: "{}",
                    allow_unsigned_fallback=False,
                )
            ]

        with pytest.raises(ValueError, match="byte limit"):
            asyncio.run(collect())

    def test_server_middleware_unwraps_request_and_wraps_jsonrpc_response(self):
        from jacs import mcp

        request_payload = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {},
        }
        response_payload = {"jsonrpc": "2.0", "id": 3, "result": {"tools": []}}
        request_envelope = _portable_test_envelope(request_payload, "request")
        response_envelope = _portable_test_envelope(response_payload, "response")
        request_carrier = mcp._build_signed_jsonrpc_carrier(
            request_payload,
            request_envelope,
        )

        class Agent:
            def verify_response_with_agent_id(self, envelope):
                assert envelope == request_envelope
                return "agent-request", request_payload

            def sign_request(self, payload):
                assert payload == response_payload
                return response_envelope

        middleware_class = mcp._build_jacs_starlette_middleware(
            Agent(),
            True,
            True,
            False,
            frozenset({"agent-request"}),
        )
        middleware = middleware_class(lambda *_args: None)
        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            method="POST",
            url=SimpleNamespace(path="/mcp"),
            body=AsyncMock(return_value=json.dumps(request_carrier).encode()),
        )

        async def response_chunks():
            yield json.dumps(response_payload).encode()

        response = SimpleNamespace(
            headers={"content-type": "application/json", "content-length": "1"},
            body_iterator=response_chunks(),
            status_code=200,
            media_type="application/json",
        )

        async def call_next(received_request):
            assert json.loads(received_request._body) == request_payload
            return response

        wrapped_response = asyncio.run(middleware.dispatch(request, call_next))
        response_carrier = json.loads(wrapped_response.body)
        assert (
            mcp._unwrap_signed_jsonrpc_carrier(
                response_carrier,
                lambda envelope: (
                    response_payload if envelope == response_envelope else None
                ),
            )
            == response_payload
        )

    @pytest.mark.parametrize("surface", ["class", "simple"])
    def test_streamable_http_mcp_post_rejects_unsigned_before_handler(
        self, monkeypatch, surface
    ):
        from jacs import mcp

        unsigned = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }
        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            method="POST",
            url=SimpleNamespace(path="/mcp"),
            body=AsyncMock(return_value=json.dumps(unsigned).encode()),
        )
        call_next = AsyncMock()
        if surface == "class":
            agent = SimpleNamespace(verify_response=lambda _envelope: unsigned)
            middleware_class = mcp._build_jacs_starlette_middleware(
                agent, True, True, False
            )
            middleware = middleware_class(lambda *_args: None)
            response = asyncio.run(middleware.dispatch(request, call_next))
        else:
            monkeypatch.setattr(mcp.simple, "is_loaded", lambda: True)
            middleware = mcp.jacs_middleware()
            response = asyncio.run(middleware(request, call_next))

        assert response.status_code == 401
        call_next.assert_not_awaited()

    def test_class_middleware_unsigned_fallback_rebuilds_consumed_response(self):
        from jacs import mcp

        raw_body = b'{"jsonrpc":"2.0","id":1,"result":{"secret":"kept"}}'

        class FailingSigner:
            def sign_request(self, _payload):
                raise RuntimeError("signing unavailable")

        async def chunks():
            yield raw_body[:11]
            yield raw_body[11:]

        response = SimpleNamespace(
            headers={"content-type": "application/json", "content-length": "1"},
            body_iterator=chunks(),
            status_code=200,
            media_type="application/json",
        )
        middleware_class = mcp._build_jacs_starlette_middleware(
            FailingSigner(), True, True, True
        )
        middleware = middleware_class(lambda *_args: None)
        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            method="GET",
            url=SimpleNamespace(path="/sse"),
        )

        rebuilt = asyncio.run(
            middleware.dispatch(request, AsyncMock(return_value=response))
        )

        assert rebuilt.body == raw_body
        assert rebuilt.headers["content-length"] == str(len(raw_body))

    def test_class_middleware_no_agent_fallback_does_not_consume_response(self):
        from jacs import mcp

        raw_body = b'{"jsonrpc":"2.0","id":1,"result":{}}'

        async def chunks():
            yield raw_body

        response = SimpleNamespace(
            headers={"content-type": "application/json"},
            body_iterator=chunks(),
            status_code=200,
            media_type="application/json",
        )
        middleware_class = mcp._build_jacs_starlette_middleware(
            SimpleNamespace(), False, True, True
        )
        middleware = middleware_class(lambda *_args: None)
        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            method="GET",
            url=SimpleNamespace(path="/sse"),
        )

        returned = asyncio.run(
            middleware.dispatch(request, AsyncMock(return_value=response))
        )

        async def consume():
            return b"".join([chunk async for chunk in returned.body_iterator])

        assert returned is response
        assert asyncio.run(consume()) == raw_body

    def test_simple_surface_uses_payload_api_and_propagates_replay_rejection(
        self, monkeypatch
    ):
        from jacs import mcp

        payload = {"jsonrpc": "2.0", "id": 11, "method": "ping", "params": {}}
        envelope = _portable_test_envelope(payload, "payload-api")

        class PayloadAgent:
            def __init__(self):
                self.verifications = 0

            def sign_request(self, received):
                assert received == payload
                return envelope

            def verify_response_with_agent_id(self, received):
                assert received == envelope
                self.verifications += 1
                if self.verifications > 1:
                    raise RuntimeError("Replay attack detected")
                return "agent-payload-api", payload

        agent = PayloadAgent()
        monkeypatch.setattr(mcp.simple, "_get_agent", lambda: agent)
        monkeypatch.setattr(mcp.simple, "is_loaded", lambda: True)

        assert mcp.sign_mcp_message(payload) == envelope
        assert (
            mcp.verify_mcp_message(
                envelope,
                expected_peer_agent_id="agent-payload-api",
            )
            == payload
        )
        with pytest.raises(
            mcp.simple.VerificationError, match="Replay attack detected"
        ):
            mcp.verify_mcp_message(
                envelope,
                expected_peer_agent_id="agent-payload-api",
            )


class TestMCPSecurityDefaults:
    """Security defaults for MCP wrappers should be hardened."""

    def test_local_only_default_enabled(self):
        from jacs import mcp

        assert mcp._resolve_local_only() is True

    def test_disabling_local_only_is_rejected(self):
        from jacs import mcp

        with pytest.raises(mcp.simple.ConfigError):
            mcp._resolve_local_only(False)

    def test_env_cannot_disable_local_only(self, monkeypatch):
        monkeypatch.setenv("JACS_MCP_LOCAL_ONLY", "false")
        from jacs import mcp

        with pytest.raises(mcp.simple.ConfigError):
            mcp._resolve_local_only()

    def test_unsigned_fallback_default_disabled(self):
        from jacs import mcp

        assert mcp._resolve_allow_unsigned_fallback() is False

    def test_bounded_body_helpers_accept_exact_limit_and_reject_one_over(self):
        from jacs import mcp

        class FakeRequest:
            headers = {}

            def __init__(self, body):
                self._value = body

            async def stream(self):
                yield self._value[:2]
                yield self._value[2:]

        async def response_chunks(value):
            yield value[:3]
            yield value[3:]

        exact_request = FakeRequest(b"12345")
        assert asyncio.run(mcp._read_bounded_request_body(exact_request, 5)) == b"12345"
        with pytest.raises(mcp._MCPMessageTooLarge):
            asyncio.run(mcp._read_bounded_request_body(FakeRequest(b"123456"), 5))

        assert (
            asyncio.run(mcp._read_bounded_response_body(response_chunks(b"12345"), 5))
            == b"12345"
        )
        with pytest.raises(mcp._MCPMessageTooLarge):
            asyncio.run(mcp._read_bounded_response_body(response_chunks(b"123456"), 5))

    def test_class_middleware_rejects_oversize_post_without_logging_payload(
        self, caplog
    ):
        from jacs import mcp

        secret = b'{"secret":"must-not-be-logged"}'

        class Request:
            client = SimpleNamespace(host="127.0.0.1")
            method = "POST"
            headers = {}

            async def stream(self):
                yield secret

        middleware_cls = mcp._build_jacs_starlette_middleware(
            SimpleNamespace(),
            False,
            True,
            True,
            max_message_bytes=len(secret) - 1,
        )
        middleware = middleware_cls(lambda *_args: None)
        call_next = AsyncMock()

        with caplog.at_level("WARNING", logger="jacs.mcp"):
            response = asyncio.run(middleware.dispatch(Request(), call_next))

        assert response.status_code == 413
        call_next.assert_not_awaited()
        assert "must-not-be-logged" not in caplog.text

    def test_strict_environment_overrides_default_false(self, monkeypatch):
        from jacs import mcp

        monkeypatch.setenv("JACS_STRICT_MODE", "true")

        assert mcp._resolve_strict(False) is True

    @pytest.mark.parametrize("surface", ["client", "server"])
    def test_strict_environment_blocks_unsigned_config_fallback(
        self, monkeypatch, surface
    ):
        from jacs import mcp

        class FailingAgent:
            def load(self, _config_path):
                raise RuntimeError("config unavailable")

        monkeypatch.setattr(mcp, "JacsAgent", FailingAgent)
        monkeypatch.setenv("JACS_STRICT_MODE", "true")
        monkeypatch.setenv("JACS_MCP_ALLOW_UNSIGNED_FALLBACK", "true")

        with pytest.raises(mcp.simple.ConfigError, match="refusing to run unsigned"):
            if surface == "client":
                mcp.JACSMCPClient("http://127.0.0.1:9000/sse")
            else:
                server = Mock()
                server.http_app = Mock(return_value=Mock())
                mcp.JACSMCPServer(server)

    def test_remote_url_rejected_in_local_mode(self):
        from jacs import mcp

        with pytest.raises(mcp.simple.ConfigError):
            mcp._enforce_local_url("https://remote.example.com/sse", "test", True)

    def test_loopback_url_allowed_in_local_mode(self):
        from jacs import mcp

        assert mcp._enforce_local_url("http://127.0.0.1:9000/sse", "test", True) is None

    def test_enforce_local_url_rejects_false_local_only(self):
        from jacs import mcp

        with pytest.raises(mcp.simple.ConfigError):
            mcp._enforce_local_url("http://localhost:9000/sse", "test", False)

    def test_middleware_rejects_remote_client(self):
        from jacs import mcp

        request = SimpleNamespace(
            client=SimpleNamespace(host="203.0.113.9"),
            url=SimpleNamespace(path="/messages/"),
            body=AsyncMock(return_value=b"{}"),
        )
        call_next = AsyncMock()
        middleware = mcp.jacs_middleware()

        if mcp.JSONResponse is None:
            with pytest.raises(mcp.simple.VerificationError):
                asyncio.run(middleware(request, call_next))
            call_next.assert_not_awaited()
        else:
            response = asyncio.run(middleware(request, call_next))
            assert response.status_code == 403
            call_next.assert_not_awaited()

    def test_middleware_allows_loopback_client(self, monkeypatch):
        from jacs import mcp

        monkeypatch.setattr(mcp.simple, "is_loaded", lambda: True)

        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            method="GET",
            url=SimpleNamespace(path="/messages/"),
            body=AsyncMock(return_value=b"{}"),
        )
        expected_response = SimpleNamespace(headers={"content-type": "text/plain"})
        call_next = AsyncMock(return_value=expected_response)
        middleware = mcp.jacs_middleware()

        response = asyncio.run(middleware(request, call_next))
        assert response is expected_response
        call_next.assert_awaited_once()


class TestMCPMiddlewareBehavior:
    """Test the middleware behavior of the MCP wrappers."""

    def test_server_wrapper_patches_http_app(self):
        """Test that the server wrapper patches http_app to inject middleware."""
        from jacs.mcp import JACSMCPServer

        original_http_app = Mock(return_value=Mock())

        mock_server = Mock()
        mock_server.http_app = original_http_app

        # Wrap the server
        wrapped = JACSMCPServer(
            mock_server,
            allow_unsigned_fallback=True,
        )

        # http_app should have been replaced with a patched version
        assert wrapped.http_app is not original_http_app

        # Call the patched http_app to trigger middleware injection
        wrapped.http_app()

        # The original http_app should have been called with middleware kwarg
        original_http_app.assert_called_once()
        _, call_kwargs = original_http_app.call_args
        assert "middleware" in call_kwargs
        assert len(call_kwargs["middleware"]) >= 1

    def test_server_wrapper_stores_middleware_class(self):
        """Test that the wrapper stores the JACS middleware class."""
        from jacs.mcp import JACSMCPServer

        mock_server = Mock()
        mock_server.http_app = Mock(return_value=Mock())

        wrapped = JACSMCPServer(
            mock_server,
            allow_unsigned_fallback=True,
        )

        assert hasattr(wrapped, "_jacs_middleware_cls")

    def test_jacs_tool_refuses_unsigned_output_when_agent_unloaded(self, monkeypatch):
        from jacs import mcp

        monkeypatch.setattr(mcp.simple, "is_loaded", lambda: False)

        @mcp.jacs_tool
        def secret_tool():
            return {"secret": "raw"}

        with pytest.raises(mcp.simple.AgentNotLoadedError):
            asyncio.run(secret_tool())

    def test_jacs_tool_unsigned_fallback_requires_explicit_opt_in(self, monkeypatch):
        from jacs import mcp

        monkeypatch.setattr(mcp.simple, "is_loaded", lambda: False)

        @mcp.jacs_tool(allow_unsigned_fallback=True)
        def legacy_tool():
            return {"legacy": "raw"}

        assert asyncio.run(legacy_tool()) == {"legacy": "raw"}

    def test_json_middleware_refuses_unsigned_output_when_agent_unloaded(
        self, monkeypatch
    ):
        from jacs import mcp

        monkeypatch.setattr(mcp.simple, "is_loaded", lambda: False)

        async def chunks():
            yield b'{"secret":"downstream"}'

        response = SimpleNamespace(
            headers={"content-type": "application/json"},
            body_iterator=chunks(),
            status_code=200,
            media_type="application/json",
        )
        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            body=AsyncMock(return_value=b"{}"),
        )
        middleware = mcp.jacs_middleware()
        result = asyncio.run(middleware(request, AsyncMock(return_value=response)))

        assert result.status_code == 503
        assert b"downstream" not in result.body

    def test_json_middleware_unsigned_fallback_requires_opt_in(self, monkeypatch):
        from jacs import mcp

        monkeypatch.setattr(mcp.simple, "is_loaded", lambda: False)
        response = SimpleNamespace(
            headers={"content-type": "application/json"},
            status_code=200,
        )
        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            body=AsyncMock(return_value=b"{}"),
        )
        middleware = mcp.jacs_middleware(allow_unsigned_fallback=True)

        result = asyncio.run(middleware(request, AsyncMock(return_value=response)))
        assert result is response


class TestMCPIntegrationTypes:
    """Test type handling in MCP integration."""

    def test_json_serialization_compatibility(self):
        """Test that types used in MCP are JSON serializable."""
        # JACS MCP integration passes data through JSON
        test_payloads = [
            {"jsonrpc": "2.0", "method": "test", "params": {}, "id": 1},
            {"jsonrpc": "2.0", "result": {"data": "value"}, "id": 1},
            {
                "jsonrpc": "2.0",
                "error": {"code": -32600, "message": "Invalid Request"},
                "id": 1,
            },
        ]

        for payload in test_payloads:
            # Should be able to serialize and deserialize
            serialized = json.dumps(payload)
            deserialized = json.loads(serialized)
            assert deserialized == payload


class TestJacsSSETransportBehavior:
    """Behavior checks for JacsSSETransport interceptors."""

    def test_is_nominal_fastmcp_transport(self):
        from fastmcp import Client
        from fastmcp.client.transports import ClientTransport
        from jacs import mcp

        transport = mcp.JacsSSETransport(
            "http://127.0.0.1:9000/sse",
            expected_peer_agent_id="server-agent",
        )

        assert isinstance(transport, ClientTransport)
        assert Client(transport) is not None

    @pytest.mark.parametrize("allow_unsigned_fallback", [False, True])
    def test_send_signing_failure_policy(self, monkeypatch, allow_unsigned_fallback):
        from jacs import mcp

        sent_payloads = []
        initialize_calls = 0

        class FakeSSETransport:
            def __init__(self, url, headers=None):
                self.url = url
                self.headers = headers

        class FakeReadStream:
            async def receive(self, **_kwargs):
                return SimpleNamespace(root={"jsonrpc": "2.0", "id": 1})

        class FakeWriteStream:
            async def send(self, message, **_kwargs):
                sent_payloads.append(message.root)

        read_stream = FakeReadStream()
        write_stream = FakeWriteStream()

        @contextlib.asynccontextmanager
        async def fake_sse_client(_url, headers=None):
            yield (read_stream, write_stream)

        class FakeClientSession:
            def __init__(self, _read_stream, _write_stream, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, _exc_type, _exc, _tb):
                return False

            async def initialize(self):
                nonlocal initialize_calls
                initialize_calls += 1
                return None

        monkeypatch.setattr(mcp, "SSETransport", FakeSSETransport)
        monkeypatch.setattr(mcp, "sse_client", fake_sse_client)
        monkeypatch.setattr(mcp, "ClientSession", FakeClientSession)
        monkeypatch.setattr(mcp.simple, "is_loaded", lambda: True)
        monkeypatch.setattr(
            mcp.simple,
            "_get_agent",
            lambda: SimpleNamespace(verify_response_with_agent_id=Mock()),
        )
        monkeypatch.setattr(
            mcp, "sign_mcp_message", Mock(side_effect=RuntimeError("sign failure"))
        )

        transport = mcp.JacsSSETransport(
            "http://127.0.0.1:9000/sse",
            allow_unsigned_fallback=allow_unsigned_fallback,
            allow_any_verified_peer=True,
        )
        message = SimpleNamespace(root={"jsonrpc": "2.0", "id": 7, "method": "ping"})

        async def run_send():
            async with transport.connect_session():
                await write_stream.send(message)

        if allow_unsigned_fallback:
            asyncio.run(run_send())
            assert sent_payloads[0]["method"] == "ping"
            assert sent_payloads[0]["id"] != 7
        else:
            with pytest.raises(mcp.simple.SigningError):
                asyncio.run(run_send())
            assert sent_payloads == []
        assert initialize_calls == 0

    def test_unloaded_agent_refuses_transport_by_default(self, monkeypatch):
        from jacs import mcp

        class FakeSSETransport:
            def __init__(self, url, headers=None):
                self.url = url
                self.headers = headers

        monkeypatch.setattr(mcp, "SSETransport", FakeSSETransport)
        monkeypatch.setattr(mcp.simple, "is_loaded", lambda: False)
        transport = mcp.JacsSSETransport("http://127.0.0.1:9000/sse")

        async def connect():
            async with transport.connect_session():
                pass

        with pytest.raises(mcp.simple.AgentNotLoadedError):
            asyncio.run(connect())


def test_jacs_call_uses_authenticated_transport(monkeypatch):
    from jacs import mcp

    created = {}

    class FakeTransport:
        def __init__(
            self,
            url,
            *,
            local_only=None,
            expected_peer_agent_id=None,
            expected_peer_public_key_hash=None,
            allow_any_verified_peer=None,
        ):
            created["url"] = url
            created["local_only"] = local_only
            created["expected_peer_agent_id"] = expected_peer_agent_id

    class FakeClient:
        def __init__(self, transport):
            created["transport"] = transport

        async def __aenter__(self):
            return self

        async def __aexit__(self, _exc_type, _exc, _tb):
            return False

        async def call_tool(self, method, params):
            return {"method": method, "params": params}

    monkeypatch.setattr(mcp.simple, "is_loaded", lambda: True)
    monkeypatch.setattr(mcp, "JacsSSETransport", FakeTransport)
    monkeypatch.setattr(mcp, "Client", FakeClient)

    result = asyncio.run(
        mcp.jacs_call(
            "http://127.0.0.1:9000/sse",
            "ping",
            expected_peer_agent_id="server-agent",
            value=7,
        )
    )

    assert created["url"] == "http://127.0.0.1:9000/sse"
    assert created["expected_peer_agent_id"] == "server-agent"
    assert isinstance(created["transport"], FakeTransport)
    assert result == {"method": "ping", "params": {"value": 7}}
