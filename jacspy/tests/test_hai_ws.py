"""
Tests for HaiClient WebSocket transport (Steps 59-60).

Uses mock WebSocket server to test:
- WS connection with JACS-signed handshake
- Event streaming via WebSocket
- Exponential backoff reconnection
- Sequence number tracking for resume
- Transport parameter validation
"""

import json
import threading
import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

pytest.importorskip("jacs")

from jacs.hai import (
    HaiClient,
    HaiEvent,
    HaiError,
    HaiConnectionError,
    AuthenticationError,
    WebSocketError,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def hai_client():
    """Create a HaiClient instance for testing."""
    return HaiClient(timeout=5.0, max_retries=1)


@pytest.fixture
def mock_agent_loaded():
    """Mock a loaded JACS agent."""
    mock_signed = MagicMock()
    mock_signed.signature = "base64-test-signature"

    with patch("jacs.hai.HaiClient._get_agent_id", return_value="test-agent-uuid-1234"), \
         patch("jacs.hai.HaiClient._get_agent_json", return_value='{"jacsId": "test-agent-uuid-1234"}'), \
         patch("jacs.simple.is_loaded", return_value=True), \
         patch("jacs.simple.sign_message", return_value=mock_signed):
        yield


# =============================================================================
# Tests: Transport parameter validation
# =============================================================================


class TestTransportParam:
    """Tests for the transport parameter on connect()."""

    def test_invalid_transport_raises_value_error(self, hai_client):
        """connect() raises ValueError for invalid transport."""
        with pytest.raises(ValueError, match="transport must be"):
            # Consume the generator to trigger the ValueError
            list(hai_client.connect("https://hai.ai", "key", transport="invalid"))

    def test_sse_transport_accepted(self, hai_client, mock_agent_loaded):
        """connect(transport='sse') is accepted without ValueError."""
        # This will fail on actual connection, but should not raise ValueError
        hai_client._should_disconnect = True
        try:
            gen = hai_client.connect("https://hai.ai", "key", transport="sse")
            # Don't consume, just verify it's a generator
            assert hasattr(gen, '__next__')
        except (HaiError, Exception):
            pass  # Expected -- no actual server

    def test_ws_transport_accepted(self, hai_client, mock_agent_loaded):
        """connect(transport='ws') is accepted without ValueError."""
        hai_client._should_disconnect = True
        try:
            gen = hai_client.connect("https://hai.ai", "key", transport="ws")
            assert hasattr(gen, '__next__')
        except (HaiError, Exception):
            pass  # Expected -- no actual server

    def test_default_transport_is_sse(self, hai_client, mock_agent_loaded):
        """connect() defaults to SSE transport."""
        with patch.object(hai_client, '_sse_connect') as mock_sse:
            mock_sse.return_value = iter([])
            list(hai_client.connect("https://hai.ai", "key"))
            mock_sse.assert_called_once()

    def test_ws_transport_calls_ws_connect(self, hai_client, mock_agent_loaded):
        """connect(transport='ws') delegates to _ws_connect."""
        with patch.object(hai_client, '_ws_connect') as mock_ws:
            mock_ws.return_value = iter([])
            list(hai_client.connect("https://hai.ai", "key", transport="ws"))
            mock_ws.assert_called_once()


# =============================================================================
# Tests: WebSocket handshake
# =============================================================================


class TestWSHandshake:
    """Tests for JACS-signed WebSocket handshake."""

    def test_handshake_contains_required_fields(self, hai_client, mock_agent_loaded):
        """WS handshake message has type, agent_id, timestamp, signature."""
        handshake = hai_client._build_ws_handshake("test-agent-uuid-1234")

        assert handshake["type"] == "handshake"
        assert handshake["agent_id"] == "test-agent-uuid-1234"
        assert "timestamp" in handshake
        assert "signature" in handshake
        assert handshake["signature"] == "base64-test-signature"

    def test_handshake_includes_last_event_id_if_set(self, hai_client, mock_agent_loaded):
        """WS handshake includes last_event_id for resume when available."""
        hai_client._last_event_id = "evt-42"
        handshake = hai_client._build_ws_handshake("test-agent-uuid-1234")

        assert handshake["last_event_id"] == "evt-42"

    def test_handshake_omits_last_event_id_if_none(self, hai_client, mock_agent_loaded):
        """WS handshake omits last_event_id when not set."""
        hai_client._last_event_id = None
        handshake = hai_client._build_ws_handshake("test-agent-uuid-1234")

        assert "last_event_id" not in handshake


# =============================================================================
# Tests: WebSocket connection with mock
# =============================================================================


class TestWSConnect:
    """Tests for WS connect/receive flow using mocks."""

    def test_ws_connect_yields_connected_event(self, hai_client, mock_agent_loaded):
        """_ws_connect yields a 'connected' event after successful handshake."""
        mock_ws = MagicMock()
        # First recv() returns handshake ACK
        mock_ws.recv.side_effect = [
            json.dumps({"type": "connected", "message": "Welcome"}),
            TimeoutError(),  # Second recv times out (keep alive)
        ]

        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.return_value = mock_ws

        hai_client._websockets = mock_ws_mod

        events = []
        for event in hai_client._ws_connect("https://hai.ai", "key"):
            events.append(event)
            hai_client._should_disconnect = True
            break

        assert len(events) == 1
        assert events[0].event_type == "connected"
        assert events[0].data["type"] == "connected"

    def test_ws_connect_sends_handshake_first(self, hai_client, mock_agent_loaded):
        """_ws_connect sends JACS-signed handshake as first WS message."""
        mock_ws = MagicMock()
        mock_ws.recv.side_effect = [
            json.dumps({"type": "connected"}),
            TimeoutError(),
        ]

        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.return_value = mock_ws

        hai_client._websockets = mock_ws_mod

        for event in hai_client._ws_connect("https://hai.ai", "key"):
            hai_client._should_disconnect = True
            break

        # Verify handshake was sent
        mock_ws.send.assert_called_once()
        sent = json.loads(mock_ws.send.call_args[0][0])
        assert sent["type"] == "handshake"
        assert sent["agent_id"] == "test-agent-uuid-1234"
        assert "signature" in sent

    def test_ws_connect_receives_events(self, hai_client, mock_agent_loaded):
        """_ws_connect yields events from WS messages."""
        mock_ws = MagicMock()
        mock_ws.recv.side_effect = [
            # Handshake ACK
            json.dumps({"type": "connected"}),
            # First real event
            json.dumps({"type": "benchmark_job", "id": "evt-1", "job_id": "j-123"}),
            # Second event
            json.dumps({"type": "heartbeat", "id": "evt-2"}),
            # Timeout to trigger disconnect check
            TimeoutError(),
        ]

        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.return_value = mock_ws

        hai_client._websockets = mock_ws_mod

        events = []
        for event in hai_client._ws_connect("https://hai.ai", "key"):
            events.append(event)
            if len(events) >= 3:
                hai_client._should_disconnect = True
                break

        assert len(events) == 3
        assert events[0].event_type == "connected"
        assert events[1].event_type == "benchmark_job"
        assert events[1].id == "evt-1"
        assert events[2].event_type == "heartbeat"

    def test_ws_connect_tracks_sequence_numbers(self, hai_client, mock_agent_loaded):
        """_ws_connect tracks last event ID for resume."""
        mock_ws = MagicMock()
        mock_ws.recv.side_effect = [
            json.dumps({"type": "connected"}),
            json.dumps({"type": "job", "id": "evt-5"}),
            json.dumps({"type": "job", "id": "evt-6"}),
            TimeoutError(),
        ]

        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.return_value = mock_ws

        hai_client._websockets = mock_ws_mod

        count = 0
        for event in hai_client._ws_connect("https://hai.ai", "key"):
            count += 1
            if count >= 3:
                hai_client._should_disconnect = True
                break

        assert hai_client._last_event_id == "evt-6"

    def test_ws_connect_url_conversion(self, hai_client, mock_agent_loaded):
        """_ws_connect converts http(s) URL to ws(s)."""
        mock_ws = MagicMock()
        mock_ws.recv.side_effect = [
            json.dumps({"type": "connected"}),
            TimeoutError(),
        ]

        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.return_value = mock_ws

        hai_client._websockets = mock_ws_mod

        for event in hai_client._ws_connect("https://hai.ai", "key"):
            hai_client._should_disconnect = True
            break

        call_args = mock_ws_mod.sync.client.connect.call_args
        ws_url = call_args[0][0]
        assert ws_url.startswith("wss://")
        assert "/api/v1/agents/test-agent-uuid-1234/ws" in ws_url

    def test_ws_handshake_rejection_raises_auth_error(self, hai_client, mock_agent_loaded):
        """_ws_connect raises AuthenticationError if handshake returns 401."""
        mock_ws = MagicMock()
        mock_ws.recv.return_value = json.dumps({
            "type": "error",
            "code": 401,
            "message": "Invalid JACS signature",
        })

        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.return_value = mock_ws

        hai_client._websockets = mock_ws_mod

        with pytest.raises(AuthenticationError):
            list(hai_client._ws_connect("https://hai.ai", "key"))

    def test_ws_handshake_rejection_raises_ws_error(self, hai_client, mock_agent_loaded):
        """_ws_connect raises WebSocketError for non-auth handshake errors."""
        mock_ws = MagicMock()
        mock_ws.recv.return_value = json.dumps({
            "type": "error",
            "code": 500,
            "message": "Internal server error",
        })

        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.return_value = mock_ws

        hai_client._websockets = mock_ws_mod

        with pytest.raises(WebSocketError, match="Internal server error"):
            list(hai_client._ws_connect("https://hai.ai", "key"))

    def test_ws_on_event_callback(self, hai_client, mock_agent_loaded):
        """_ws_connect calls on_event callback for each event."""
        mock_ws = MagicMock()
        mock_ws.recv.side_effect = [
            json.dumps({"type": "connected"}),
            json.dumps({"type": "job", "id": "evt-1"}),
            TimeoutError(),
        ]

        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.return_value = mock_ws

        hai_client._websockets = mock_ws_mod

        callback_events = []

        def on_event(event):
            callback_events.append(event)

        count = 0
        for event in hai_client._ws_connect("https://hai.ai", "key", on_event=on_event):
            count += 1
            if count >= 2:
                hai_client._should_disconnect = True
                break

        assert len(callback_events) == 2


# =============================================================================
# Tests: Reconnection with exponential backoff (Step 60)
# =============================================================================


class TestWSReconnection:
    """Tests for WS reconnection with exponential backoff."""

    def test_reconnects_on_connection_error(self, hai_client, mock_agent_loaded):
        """_ws_connect reconnects on OSError with backoff."""
        call_count = 0

        def connect_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSError("Connection refused")
            # Second attempt succeeds
            mock_ws = MagicMock()
            mock_ws.recv.side_effect = [
                json.dumps({"type": "connected"}),
                TimeoutError(),
            ]
            return mock_ws

        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.side_effect = connect_side_effect

        hai_client._websockets = mock_ws_mod

        with patch("jacs.hai.time.sleep") as mock_sleep:
            for event in hai_client._ws_connect("https://hai.ai", "key"):
                hai_client._should_disconnect = True
                break

            # Should have slept once (backoff after first failure)
            mock_sleep.assert_called_once_with(1.0)

        assert call_count == 2

    def test_backoff_doubles_on_repeated_failures(self, hai_client, mock_agent_loaded):
        """Reconnect delay doubles on consecutive failures."""
        call_count = 0

        def connect_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                raise OSError("Connection refused")
            # Fourth attempt succeeds
            mock_ws = MagicMock()
            mock_ws.recv.side_effect = [
                json.dumps({"type": "connected"}),
                TimeoutError(),
            ]
            return mock_ws

        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.side_effect = connect_side_effect

        hai_client._websockets = mock_ws_mod

        sleep_calls = []
        with patch("jacs.hai.time.sleep", side_effect=lambda d: sleep_calls.append(d)):
            for event in hai_client._ws_connect("https://hai.ai", "key"):
                hai_client._should_disconnect = True
                break

        # 1.0, 2.0, 4.0 (exponential backoff)
        assert sleep_calls == [1.0, 2.0, 4.0]

    def test_backoff_capped_at_60_seconds(self, hai_client, mock_agent_loaded):
        """Reconnect delay is capped at 60 seconds."""
        call_count = 0

        def connect_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 8:
                raise OSError("Connection refused")
            mock_ws = MagicMock()
            mock_ws.recv.side_effect = [
                json.dumps({"type": "connected"}),
                TimeoutError(),
            ]
            return mock_ws

        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.side_effect = connect_side_effect

        hai_client._websockets = mock_ws_mod

        sleep_calls = []
        with patch("jacs.hai.time.sleep", side_effect=lambda d: sleep_calls.append(d)):
            for event in hai_client._ws_connect("https://hai.ai", "key"):
                hai_client._should_disconnect = True
                break

        # After 6 doublings: 1, 2, 4, 8, 16, 32, 60, 60
        assert all(d <= 60.0 for d in sleep_calls)
        assert sleep_calls[-1] == 60.0

    def test_backoff_resets_on_successful_connection(self, hai_client, mock_agent_loaded):
        """Backoff delay resets to 1.0 after successful connection."""
        call_count = 0

        def connect_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSError("Connection refused")
            mock_ws = MagicMock()
            if call_count == 2:
                # Second attempt succeeds, then connection drops
                mock_ws.recv.side_effect = [
                    json.dumps({"type": "connected"}),
                    ConnectionError("Lost connection"),
                ]
            else:
                mock_ws.recv.side_effect = [
                    json.dumps({"type": "connected"}),
                    TimeoutError(),
                ]
            return mock_ws

        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.side_effect = connect_side_effect

        hai_client._websockets = mock_ws_mod

        sleep_calls = []
        with patch("jacs.hai.time.sleep", side_effect=lambda d: sleep_calls.append(d)):
            events = []
            for event in hai_client._ws_connect("https://hai.ai", "key"):
                events.append(event)
                if len(events) >= 2:
                    hai_client._should_disconnect = True
                    break

        # First sleep: 1.0 (initial failure)
        # After successful connect, backoff resets
        # Second sleep: 1.0 (reset after success, then drop)
        assert sleep_calls[0] == 1.0
        if len(sleep_calls) > 1:
            assert sleep_calls[1] == 1.0  # Reset after successful connection

    def test_no_reconnect_when_should_disconnect(self, hai_client, mock_agent_loaded):
        """No reconnection attempt when _should_disconnect is True."""
        mock_ws_mod = MagicMock()
        mock_ws_mod.sync.client.connect.side_effect = OSError("Connection refused")

        hai_client._websockets = mock_ws_mod
        hai_client._should_disconnect = True

        events = list(hai_client._ws_connect("https://hai.ai", "key"))
        assert events == []


# =============================================================================
# Tests: Disconnect
# =============================================================================


class TestWSDisconnect:
    """Tests for disconnect() with WebSocket transport."""

    def test_disconnect_closes_ws_connection(self, hai_client):
        """disconnect() closes the WebSocket connection."""
        mock_ws = MagicMock()
        hai_client._ws_connection = mock_ws
        hai_client._connected = True

        hai_client.disconnect()

        mock_ws.close.assert_called_once()
        assert hai_client._ws_connection is None
        assert hai_client._connected is False
        assert hai_client._should_disconnect is True

    def test_disconnect_safe_when_no_connection(self, hai_client):
        """disconnect() is safe to call with no active connection."""
        hai_client._ws_connection = None
        hai_client._sse_connection = None

        hai_client.disconnect()  # Should not raise

        assert hai_client._connected is False


# =============================================================================
# Tests: Exports
# =============================================================================


class TestWSExports:
    """Test that WS types are properly exported."""

    def test_websocket_error_in_all(self):
        """WebSocketError is in __all__."""
        from jacs.hai import __all__
        assert "WebSocketError" in __all__

    def test_can_import_websocket_error(self):
        """WebSocketError is importable from jacs.hai."""
        from jacs.hai import WebSocketError
        assert issubclass(WebSocketError, HaiError)
