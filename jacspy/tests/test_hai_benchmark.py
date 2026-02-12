"""
Tests for HaiClient.free_chaotic_run() and HaiClient.baseline_run().

MVP Steps 88-89: Three-tier benchmark SDK methods.

Uses mock HTTP responses since the backend endpoints are not yet fully wired.
"""

import json
import time
from unittest.mock import MagicMock, patch, call

import pytest

# Skip all tests if jacs module is not available
pytest.importorskip("jacs")

from jacs.hai import (
    HaiClient,
    FreeChaoticResult,
    BaselineRunResult,
    JobResponseResult,
    TranscriptMessage,
    HaiError,
    HaiConnectionError,
    AuthenticationError,
    BenchmarkError,
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


@pytest.fixture
def mock_httpx():
    """Create a mock httpx module with proper exception classes."""
    mock = MagicMock()
    mock.ConnectError = type("ConnectError", (Exception,), {})
    mock.TimeoutException = type("TimeoutException", (Exception,), {})
    return mock


@pytest.fixture
def sample_transcript():
    """Sample transcript messages from a benchmark run."""
    return [
        {
            "role": "system",
            "content": "Mediation session begins.",
            "timestamp": "2026-02-11T22:00:00Z",
            "annotations": ["Session started"],
        },
        {
            "role": "party_a",
            "content": "I want to dissolve the partnership.",
            "timestamp": "2026-02-11T22:00:01Z",
            "annotations": [],
        },
        {
            "role": "party_b",
            "content": "I disagree with the proposed terms.",
            "timestamp": "2026-02-11T22:00:02Z",
            "annotations": ["Dispute escalated"],
        },
        {
            "role": "mediator",
            "content": "Let's find common ground. What are your priorities?",
            "timestamp": "2026-02-11T22:00:03Z",
            "annotations": ["Resolution attempted"],
        },
        {
            "role": "system",
            "content": "Session ended.",
            "timestamp": "2026-02-11T22:00:30Z",
            "annotations": ["Session complete"],
        },
    ]


# =============================================================================
# Tests: TranscriptMessage
# =============================================================================


class TestTranscriptMessage:
    """Tests for TranscriptMessage dataclass."""

    def test_defaults(self):
        """TranscriptMessage has correct defaults."""
        msg = TranscriptMessage(role="mediator", content="Hello")
        assert msg.role == "mediator"
        assert msg.content == "Hello"
        assert msg.timestamp == ""
        assert msg.annotations == []

    def test_full_construction(self):
        """TranscriptMessage accepts all fields."""
        msg = TranscriptMessage(
            role="party_a",
            content="I disagree.",
            timestamp="2026-02-11T22:00:00Z",
            annotations=["Dispute escalated"],
        )
        assert msg.role == "party_a"
        assert msg.annotations == ["Dispute escalated"]


# =============================================================================
# Tests: FreeChaoticResult
# =============================================================================


class TestFreeChaoticResult:
    """Tests for FreeChaoticResult dataclass."""

    def test_defaults(self):
        """FreeChaoticResult has correct defaults."""
        result = FreeChaoticResult(success=True)
        assert result.success is True
        assert result.run_id == ""
        assert result.transcript == []
        assert result.upsell_message == ""
        assert result.raw_response == {}

    def test_with_transcript(self):
        """FreeChaoticResult holds transcript messages."""
        msgs = [TranscriptMessage(role="mediator", content="Let's talk.")]
        result = FreeChaoticResult(
            success=True,
            run_id="run-123",
            transcript=msgs,
            upsell_message="$5 to see your score",
        )
        assert len(result.transcript) == 1
        assert result.transcript[0].role == "mediator"
        assert result.upsell_message == "$5 to see your score"


# =============================================================================
# Tests: BaselineRunResult
# =============================================================================


class TestBaselineRunResult:
    """Tests for BaselineRunResult dataclass."""

    def test_defaults(self):
        """BaselineRunResult has correct defaults."""
        result = BaselineRunResult(success=True)
        assert result.success is True
        assert result.run_id == ""
        assert result.score == 0.0
        assert result.transcript == []
        assert result.payment_id == ""
        assert result.raw_response == {}

    def test_with_score(self):
        """BaselineRunResult holds score and payment info."""
        result = BaselineRunResult(
            success=True,
            run_id="run-456",
            score=72.5,
            payment_id="pay-789",
        )
        assert result.score == 72.5
        assert result.payment_id == "pay-789"


# =============================================================================
# Tests: HaiClient.free_chaotic_run()
# =============================================================================


class TestFreeChaoticRun:
    """Tests for HaiClient.free_chaotic_run() -- MVP Step 88."""

    def test_success(self, hai_client, mock_agent_loaded, mock_httpx, sample_transcript):
        """free_chaotic_run() returns FreeChaoticResult on success."""
        response_data = {
            "run_id": "run-chaotic-001",
            "transcript": sample_transcript,
            "upsell_message": "$5 to see your score",
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response_data
        mock_resp.text = json.dumps(response_data)

        mock_httpx.post.return_value = mock_resp
        hai_client._httpx = mock_httpx

        result = hai_client.free_chaotic_run("https://hai.ai", api_key="test-key")

        assert isinstance(result, FreeChaoticResult)
        assert result.success is True
        assert result.run_id == "run-chaotic-001"
        assert len(result.transcript) == 5
        assert result.transcript[0].role == "system"
        assert result.transcript[3].role == "mediator"
        assert result.upsell_message == "$5 to see your score"

    def test_correct_url_and_tier(self, hai_client, mock_agent_loaded, mock_httpx, sample_transcript):
        """free_chaotic_run() POSTs to /api/benchmark/run with tier=free_chaotic."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"transcript": sample_transcript}
        mock_httpx.post.return_value = mock_resp
        hai_client._httpx = mock_httpx

        hai_client.free_chaotic_run("https://hai.ai", api_key="test-key")

        call_args = mock_httpx.post.call_args
        url = call_args[0][0] if call_args[0] else call_args.kwargs.get("url", "")
        assert url == "https://hai.ai/api/benchmark/run"

        payload = call_args.kwargs.get("json") or call_args[1].get("json", {})
        assert payload["tier"] == "free_chaotic"

    def test_jacs_auth_header(self, hai_client, mock_agent_loaded, mock_httpx, sample_transcript):
        """free_chaotic_run() sends JACS auth header."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"transcript": sample_transcript}
        mock_httpx.post.return_value = mock_resp
        hai_client._httpx = mock_httpx

        hai_client.free_chaotic_run("https://hai.ai", api_key="test-key")

        call_kwargs = mock_httpx.post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("JACS ")

    def test_429_rate_limit(self, hai_client, mock_agent_loaded, mock_httpx):
        """free_chaotic_run() raises HaiError on 429."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = ""
        mock_httpx.post.return_value = mock_resp
        hai_client._httpx = mock_httpx

        with pytest.raises(HaiError) as exc_info:
            hai_client.free_chaotic_run("https://hai.ai")

        assert exc_info.value.status_code == 429
        assert "Rate limited" in str(exc_info.value)

    def test_401_auth_error(self, hai_client, mock_agent_loaded, mock_httpx):
        """free_chaotic_run() raises AuthenticationError on 401."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {"error": "Invalid JACS signature"}
        mock_resp.text = '{"error": "Invalid JACS signature"}'
        mock_httpx.post.return_value = mock_resp
        hai_client._httpx = mock_httpx

        with pytest.raises(AuthenticationError):
            hai_client.free_chaotic_run("https://hai.ai")

    def test_connection_error(self, hai_client, mock_agent_loaded, mock_httpx):
        """free_chaotic_run() raises HaiConnectionError on network failure."""
        mock_httpx.post.side_effect = mock_httpx.ConnectError("Connection refused")
        hai_client._httpx = mock_httpx

        with pytest.raises(HaiConnectionError):
            hai_client.free_chaotic_run("https://hai.ai")

    def test_no_agent_loaded(self, hai_client):
        """free_chaotic_run() raises HaiError when no agent is loaded."""
        with patch("jacs.hai.HaiClient._get_agent_id", side_effect=Exception("No agent")):
            with pytest.raises(HaiError):
                hai_client.free_chaotic_run("https://hai.ai")

    def test_transcript_parsing(self, hai_client, mock_agent_loaded, mock_httpx):
        """free_chaotic_run() correctly parses transcript with annotations."""
        transcript_data = [
            {
                "role": "mediator",
                "content": "Welcome.",
                "timestamp": "2026-02-11T22:00:00Z",
                "annotations": ["Session started", "Greeting"],
            },
        ]

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "run_id": "run-001",
            "transcript": transcript_data,
        }
        mock_httpx.post.return_value = mock_resp
        hai_client._httpx = mock_httpx

        result = hai_client.free_chaotic_run("https://hai.ai")

        assert len(result.transcript) == 1
        msg = result.transcript[0]
        assert isinstance(msg, TranscriptMessage)
        assert msg.role == "mediator"
        assert msg.content == "Welcome."
        assert msg.timestamp == "2026-02-11T22:00:00Z"
        assert msg.annotations == ["Session started", "Greeting"]

    def test_empty_transcript(self, hai_client, mock_agent_loaded, mock_httpx):
        """free_chaotic_run() handles empty transcript."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"run_id": "run-001", "transcript": []}
        mock_httpx.post.return_value = mock_resp
        hai_client._httpx = mock_httpx

        result = hai_client.free_chaotic_run("https://hai.ai")
        assert result.success is True
        assert result.transcript == []

    def test_preserves_raw_response(self, hai_client, mock_agent_loaded, mock_httpx, sample_transcript):
        """free_chaotic_run() preserves full raw response."""
        response_data = {
            "run_id": "run-001",
            "transcript": sample_transcript,
            "extra_field": "preserved",
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response_data
        mock_httpx.post.return_value = mock_resp
        hai_client._httpx = mock_httpx

        result = hai_client.free_chaotic_run("https://hai.ai")
        assert result.raw_response["extra_field"] == "preserved"


# =============================================================================
# Tests: HaiClient.baseline_run()
# =============================================================================


class TestBaselineRun:
    """Tests for HaiClient.baseline_run() -- MVP Step 89."""

    def _mock_baseline_flow(self, mock_httpx, sample_transcript, score=72.5):
        """Set up mock responses for the full baseline flow."""
        # Purchase response
        purchase_resp = MagicMock()
        purchase_resp.status_code = 200
        purchase_resp.json.return_value = {
            "checkout_url": "https://checkout.stripe.com/test",
            "payment_id": "pay-test-001",
        }
        purchase_resp.text = "ok"

        # Payment status response (paid)
        status_resp = MagicMock()
        status_resp.status_code = 200
        status_resp.json.return_value = {"status": "paid"}

        # Benchmark run response
        run_resp = MagicMock()
        run_resp.status_code = 200
        run_resp.json.return_value = {
            "run_id": "run-baseline-001",
            "score": score,
            "transcript": sample_transcript,
        }
        run_resp.text = json.dumps({"score": score})

        # POST for purchase, GET for payment status, POST for run
        mock_httpx.post.side_effect = [purchase_resp, run_resp]
        mock_httpx.get.return_value = status_resp

    def test_success(self, hai_client, mock_agent_loaded, mock_httpx, sample_transcript):
        """baseline_run() returns BaselineRunResult with score on success."""
        self._mock_baseline_flow(mock_httpx, sample_transcript, score=72.5)
        hai_client._httpx = mock_httpx

        with patch("webbrowser.open"):
            result = hai_client.baseline_run(
                "https://hai.ai",
                api_key="test-key",
                open_browser=False,
            )

        assert isinstance(result, BaselineRunResult)
        assert result.success is True
        assert result.score == 72.5
        assert result.run_id == "run-baseline-001"
        assert result.payment_id == "pay-test-001"
        assert len(result.transcript) == 5

    def test_creates_purchase(self, hai_client, mock_agent_loaded, mock_httpx, sample_transcript):
        """baseline_run() creates a Stripe checkout session."""
        self._mock_baseline_flow(mock_httpx, sample_transcript)
        hai_client._httpx = mock_httpx

        hai_client.baseline_run(
            "https://hai.ai",
            api_key="test-key",
            open_browser=False,
        )

        # First POST is purchase
        first_call = mock_httpx.post.call_args_list[0]
        url = first_call[0][0] if first_call[0] else first_call.kwargs.get("url", "")
        assert url == "https://hai.ai/api/benchmark/purchase"

        payload = first_call.kwargs.get("json") or first_call[1].get("json", {})
        assert payload["tier"] == "baseline"
        assert payload["agent_id"] == "test-agent-uuid-1234"

    def test_opens_browser(self, hai_client, mock_agent_loaded, mock_httpx, sample_transcript):
        """baseline_run() opens browser for Stripe checkout."""
        self._mock_baseline_flow(mock_httpx, sample_transcript)
        hai_client._httpx = mock_httpx

        with patch("webbrowser.open") as mock_open:
            hai_client.baseline_run(
                "https://hai.ai",
                api_key="test-key",
                open_browser=True,
            )
            mock_open.assert_called_once_with("https://checkout.stripe.com/test")

    def test_skips_browser_when_disabled(self, hai_client, mock_agent_loaded, mock_httpx, sample_transcript):
        """baseline_run(open_browser=False) does not open browser."""
        self._mock_baseline_flow(mock_httpx, sample_transcript)
        hai_client._httpx = mock_httpx

        with patch("webbrowser.open") as mock_open:
            hai_client.baseline_run(
                "https://hai.ai",
                api_key="test-key",
                open_browser=False,
            )
            mock_open.assert_not_called()

    def test_polls_payment_status(self, hai_client, mock_agent_loaded, mock_httpx, sample_transcript):
        """baseline_run() polls for payment confirmation."""
        self._mock_baseline_flow(mock_httpx, sample_transcript)
        hai_client._httpx = mock_httpx

        hai_client.baseline_run(
            "https://hai.ai",
            api_key="test-key",
            open_browser=False,
        )

        # GET was called for payment status
        mock_httpx.get.assert_called()
        status_call = mock_httpx.get.call_args
        url = status_call[0][0] if status_call[0] else status_call.kwargs.get("url", "")
        assert "/api/benchmark/payments/pay-test-001/status" in url

    def test_payment_timeout(self, hai_client, mock_agent_loaded, mock_httpx):
        """baseline_run() raises BenchmarkError on payment timeout."""
        # Purchase succeeds
        purchase_resp = MagicMock()
        purchase_resp.status_code = 200
        purchase_resp.json.return_value = {
            "checkout_url": "https://checkout.stripe.com/test",
            "payment_id": "pay-test-001",
        }
        purchase_resp.text = "ok"
        mock_httpx.post.return_value = purchase_resp

        # Payment never becomes "paid"
        status_resp = MagicMock()
        status_resp.status_code = 200
        status_resp.json.return_value = {"status": "pending"}
        mock_httpx.get.return_value = status_resp

        hai_client._httpx = mock_httpx

        with pytest.raises(BenchmarkError, match="Payment not confirmed"):
            hai_client.baseline_run(
                "https://hai.ai",
                api_key="test-key",
                open_browser=False,
                payment_poll_timeout=0.1,
                payment_poll_interval=0.05,
            )

    def test_payment_failed(self, hai_client, mock_agent_loaded, mock_httpx):
        """baseline_run() raises BenchmarkError when payment fails."""
        purchase_resp = MagicMock()
        purchase_resp.status_code = 200
        purchase_resp.json.return_value = {
            "checkout_url": "https://checkout.stripe.com/test",
            "payment_id": "pay-test-001",
        }
        purchase_resp.text = "ok"
        mock_httpx.post.return_value = purchase_resp

        status_resp = MagicMock()
        status_resp.status_code = 200
        status_resp.json.return_value = {"status": "failed", "message": "Card declined"}
        mock_httpx.get.return_value = status_resp

        hai_client._httpx = mock_httpx

        with pytest.raises(BenchmarkError, match="Payment failed"):
            hai_client.baseline_run(
                "https://hai.ai",
                api_key="test-key",
                open_browser=False,
            )

    def test_purchase_auth_error(self, hai_client, mock_agent_loaded, mock_httpx):
        """baseline_run() raises AuthenticationError on 401 during purchase."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {"error": "Invalid API key"}
        mock_resp.text = '{"error": "Invalid API key"}'
        mock_httpx.post.return_value = mock_resp

        hai_client._httpx = mock_httpx

        with pytest.raises(AuthenticationError):
            hai_client.baseline_run(
                "https://hai.ai",
                api_key="bad-key",
                open_browser=False,
            )

    def test_no_checkout_url(self, hai_client, mock_agent_loaded, mock_httpx):
        """baseline_run() raises BenchmarkError when no checkout URL returned."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"payment_id": "pay-001"}
        mock_resp.text = "ok"
        mock_httpx.post.return_value = mock_resp

        hai_client._httpx = mock_httpx

        with pytest.raises(BenchmarkError, match="No checkout URL"):
            hai_client.baseline_run(
                "https://hai.ai",
                api_key="test-key",
                open_browser=False,
            )

    def test_run_sends_payment_id(self, hai_client, mock_agent_loaded, mock_httpx, sample_transcript):
        """baseline_run() sends payment_id in the run request."""
        self._mock_baseline_flow(mock_httpx, sample_transcript)
        hai_client._httpx = mock_httpx

        hai_client.baseline_run(
            "https://hai.ai",
            api_key="test-key",
            open_browser=False,
        )

        # Second POST is the benchmark run
        run_call = mock_httpx.post.call_args_list[1]
        payload = run_call.kwargs.get("json") or run_call[1].get("json", {})
        assert payload["payment_id"] == "pay-test-001"
        assert payload["tier"] == "baseline"

    def test_run_failure(self, hai_client, mock_agent_loaded, mock_httpx):
        """baseline_run() raises BenchmarkError when run fails."""
        # Purchase succeeds
        purchase_resp = MagicMock()
        purchase_resp.status_code = 200
        purchase_resp.json.return_value = {
            "checkout_url": "https://checkout.stripe.com/test",
            "payment_id": "pay-test-001",
        }
        purchase_resp.text = "ok"

        # Payment confirmed
        status_resp = MagicMock()
        status_resp.status_code = 200
        status_resp.json.return_value = {"status": "paid"}
        mock_httpx.get.return_value = status_resp

        # Run fails
        run_resp = MagicMock()
        run_resp.status_code = 500
        run_resp.json.return_value = {"error": "Internal error"}
        run_resp.text = '{"error": "Internal error"}'

        mock_httpx.post.side_effect = [purchase_resp, run_resp]
        hai_client._httpx = mock_httpx

        with pytest.raises(BenchmarkError):
            hai_client.baseline_run(
                "https://hai.ai",
                api_key="test-key",
                open_browser=False,
            )

    def test_score_is_float(self, hai_client, mock_agent_loaded, mock_httpx, sample_transcript):
        """baseline_run() converts score to float."""
        self._mock_baseline_flow(mock_httpx, sample_transcript, score=85)
        hai_client._httpx = mock_httpx

        result = hai_client.baseline_run(
            "https://hai.ai",
            api_key="test-key",
            open_browser=False,
        )

        assert isinstance(result.score, float)
        assert result.score == 85.0


# =============================================================================
# Tests: Module-level convenience functions
# =============================================================================


class TestModuleLevelBenchmarkFunctions:
    """Tests for module-level free_chaotic_run() and baseline_run()."""

    def test_free_chaotic_run_delegates(self):
        """Module-level free_chaotic_run() delegates to HaiClient."""
        from jacs import hai

        mock_result = FreeChaoticResult(success=True, run_id="run-001")

        with patch.object(HaiClient, "free_chaotic_run", return_value=mock_result) as mock_method:
            result = hai.free_chaotic_run("https://hai.ai", api_key="key")
            assert result.success is True
            mock_method.assert_called_once_with("https://hai.ai", "key", "sse")

    def test_baseline_run_delegates(self):
        """Module-level baseline_run() delegates to HaiClient."""
        from jacs import hai

        mock_result = BaselineRunResult(success=True, score=72.0)

        with patch.object(HaiClient, "baseline_run", return_value=mock_result) as mock_method:
            result = hai.baseline_run("https://hai.ai", api_key="key", open_browser=False)
            assert result.success is True
            mock_method.assert_called_once_with("https://hai.ai", "key", "sse", False)


# =============================================================================
# Tests: Exports
# =============================================================================


class TestBenchmarkExports:
    """Test that new types are properly exported."""

    def test_transcript_message_in_all(self):
        from jacs.hai import __all__
        assert "TranscriptMessage" in __all__

    def test_free_chaotic_result_in_all(self):
        from jacs.hai import __all__
        assert "FreeChaoticResult" in __all__

    def test_baseline_run_result_in_all(self):
        from jacs.hai import __all__
        assert "BaselineRunResult" in __all__

    def test_free_chaotic_run_function_in_all(self):
        from jacs.hai import __all__
        assert "free_chaotic_run" in __all__

    def test_baseline_run_function_in_all(self):
        from jacs.hai import __all__
        assert "baseline_run" in __all__

    def test_can_import_all_new_types(self):
        from jacs.hai import TranscriptMessage, FreeChaoticResult, BaselineRunResult
        assert TranscriptMessage is not None
        assert FreeChaoticResult is not None
        assert BaselineRunResult is not None

    def test_can_import_all_new_functions(self):
        from jacs.hai import free_chaotic_run, baseline_run
        assert callable(free_chaotic_run)
        assert callable(baseline_run)

    def test_job_response_result_in_all(self):
        from jacs.hai import __all__
        assert "JobResponseResult" in __all__

    def test_submit_benchmark_response_in_all(self):
        from jacs.hai import __all__
        assert "submit_benchmark_response" in __all__

    def test_can_import_job_response_types(self):
        from jacs.hai import JobResponseResult, submit_benchmark_response
        assert JobResponseResult is not None
        assert callable(submit_benchmark_response)


# =============================================================================
# Tests: submit_benchmark_response()
# =============================================================================


class TestSubmitBenchmarkResponse:
    """Tests for HaiClient.submit_benchmark_response().

    MVP Step 98: POST /api/v1/agents/jobs/{job_id}/response with
    JACS-signed ModerationResponse.
    """

    def test_success(self, hai_client, mock_agent_loaded, mock_httpx):
        """submit_benchmark_response() returns JobResponseResult on success."""
        from jacs.hai import JobResponseResult

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "success": True,
            "job_id": "job-001",
            "message": "Response accepted",
        }
        resp.text = "ok"
        mock_httpx.post.return_value = resp
        hai_client._httpx = mock_httpx

        result = hai_client.submit_benchmark_response(
            "https://hai.ai",
            job_id="job-001",
            message="This dispute seems resolvable.",
            api_key="test-key",
        )

        assert isinstance(result, JobResponseResult)
        assert result.success is True
        assert result.job_id == "job-001"
        assert result.message == "Response accepted"

    def test_url_includes_job_id(self, hai_client, mock_agent_loaded, mock_httpx):
        """submit_benchmark_response() posts to /api/v1/agents/jobs/{job_id}/response."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "success": True,
            "job_id": "job-abc-123",
            "message": "ok",
        }
        resp.text = "ok"
        mock_httpx.post.return_value = resp
        hai_client._httpx = mock_httpx

        hai_client.submit_benchmark_response(
            "https://hai.ai",
            job_id="job-abc-123",
            message="Response text",
            api_key="test-key",
        )

        call_args = mock_httpx.post.call_args
        url = call_args[0][0] if call_args[0] else call_args.kwargs.get("url", "")
        assert url == "https://hai.ai/api/v1/agents/jobs/job-abc-123/response"

    def test_sends_jacs_auth_header(self, hai_client, mock_agent_loaded, mock_httpx):
        """submit_benchmark_response() includes JACS Authorization header."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"success": True, "job_id": "j1", "message": "ok"}
        resp.text = "ok"
        mock_httpx.post.return_value = resp
        hai_client._httpx = mock_httpx

        hai_client.submit_benchmark_response(
            "https://hai.ai",
            job_id="j1",
            message="response",
            api_key="test-key",
        )

        call_args = mock_httpx.post.call_args
        headers = call_args.kwargs.get("headers") or call_args[1].get("headers", {})
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("JACS test-agent-uuid-1234:")

    def test_payload_structure(self, hai_client, mock_agent_loaded, mock_httpx):
        """submit_benchmark_response() sends correct ModerationResponse payload."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"success": True, "job_id": "j1", "message": "ok"}
        resp.text = "ok"
        mock_httpx.post.return_value = resp
        hai_client._httpx = mock_httpx

        hai_client.submit_benchmark_response(
            "https://hai.ai",
            job_id="j1",
            message="I recommend a fair split.",
            metadata={"confidence": 0.85, "strategy": "collaborative"},
            processing_time_ms=1500,
            api_key="test-key",
        )

        call_args = mock_httpx.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json", {})
        assert "response" in payload
        assert payload["response"]["message"] == "I recommend a fair split."
        assert payload["response"]["metadata"] == {"confidence": 0.85, "strategy": "collaborative"}
        assert payload["response"]["processing_time_ms"] == 1500

    def test_payload_without_optional_fields(self, hai_client, mock_agent_loaded, mock_httpx):
        """submit_benchmark_response() omits metadata/processing_time_ms when not provided."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"success": True, "job_id": "j1", "message": "ok"}
        resp.text = "ok"
        mock_httpx.post.return_value = resp
        hai_client._httpx = mock_httpx

        hai_client.submit_benchmark_response(
            "https://hai.ai",
            job_id="j1",
            message="Simple response",
            api_key="test-key",
        )

        call_args = mock_httpx.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json", {})
        assert "response" in payload
        assert payload["response"]["message"] == "Simple response"
        assert "metadata" not in payload["response"]
        assert "processing_time_ms" not in payload["response"]

    def test_401_raises_auth_error(self, hai_client, mock_agent_loaded, mock_httpx):
        """submit_benchmark_response() raises AuthenticationError on 401."""
        resp = MagicMock()
        resp.status_code = 401
        resp.json.return_value = {"error": "Invalid signature"}
        resp.text = '{"error": "Invalid signature"}'
        mock_httpx.post.return_value = resp
        hai_client._httpx = mock_httpx

        with pytest.raises(AuthenticationError):
            hai_client.submit_benchmark_response(
                "https://hai.ai",
                job_id="j1",
                message="response",
                api_key="test-key",
            )

    def test_404_raises_benchmark_error(self, hai_client, mock_agent_loaded, mock_httpx):
        """submit_benchmark_response() raises BenchmarkError on 404 (job not found)."""
        resp = MagicMock()
        resp.status_code = 404
        resp.json.return_value = {"error": "Job not found"}
        resp.text = '{"error": "Job not found"}'
        mock_httpx.post.return_value = resp
        hai_client._httpx = mock_httpx

        with pytest.raises(BenchmarkError, match="Job not found"):
            hai_client.submit_benchmark_response(
                "https://hai.ai",
                job_id="nonexistent-job",
                message="response",
                api_key="test-key",
            )

    def test_500_raises_benchmark_error(self, hai_client, mock_agent_loaded, mock_httpx):
        """submit_benchmark_response() raises BenchmarkError on 500."""
        resp = MagicMock()
        resp.status_code = 500
        resp.json.return_value = {"error": "Internal error"}
        resp.text = "error"
        mock_httpx.post.return_value = resp
        hai_client._httpx = mock_httpx

        with pytest.raises(BenchmarkError, match="rejected"):
            hai_client.submit_benchmark_response(
                "https://hai.ai",
                job_id="j1",
                message="response",
                api_key="test-key",
            )

    def test_connection_error(self, hai_client, mock_agent_loaded, mock_httpx):
        """submit_benchmark_response() raises HaiConnectionError on connect failure."""
        mock_httpx.post.side_effect = mock_httpx.ConnectError("Connection refused")
        hai_client._httpx = mock_httpx

        with pytest.raises(HaiConnectionError, match="Connection failed"):
            hai_client.submit_benchmark_response(
                "https://hai.ai",
                job_id="j1",
                message="response",
                api_key="test-key",
            )

    def test_no_agent_raises_error(self, hai_client, mock_httpx):
        """submit_benchmark_response() raises HaiError if no agent loaded."""
        hai_client._httpx = mock_httpx

        with patch("jacs.hai.HaiClient._get_agent_id", side_effect=Exception("No agent")):
            with pytest.raises(HaiError, match="Failed to get agent ID"):
                hai_client.submit_benchmark_response(
                    "https://hai.ai",
                    job_id="j1",
                    message="response",
                    api_key="test-key",
                )

    def test_raw_response_preserved(self, hai_client, mock_agent_loaded, mock_httpx):
        """submit_benchmark_response() preserves full raw response."""
        raw = {
            "success": True,
            "job_id": "job-001",
            "message": "Response accepted",
            "extra_field": "extra_value",
        }
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = raw
        resp.text = "ok"
        mock_httpx.post.return_value = resp
        hai_client._httpx = mock_httpx

        result = hai_client.submit_benchmark_response(
            "https://hai.ai",
            job_id="job-001",
            message="response",
            api_key="test-key",
        )

        assert result.raw_response == raw
        assert result.raw_response["extra_field"] == "extra_value"

    def test_api_key_from_env(self, hai_client, mock_agent_loaded, mock_httpx):
        """submit_benchmark_response() reads API key from HAI_API_KEY env var."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"success": True, "job_id": "j1", "message": "ok"}
        resp.text = "ok"
        mock_httpx.post.return_value = resp
        hai_client._httpx = mock_httpx

        with patch.dict("os.environ", {"HAI_API_KEY": "env-key-123"}):
            hai_client.submit_benchmark_response(
                "https://hai.ai",
                job_id="j1",
                message="response",
            )

        call_args = mock_httpx.post.call_args
        headers = call_args.kwargs.get("headers") or call_args[1].get("headers", {})
        assert headers.get("X-API-Key") == "env-key-123"


class TestSubmitBenchmarkResponseModuleLevel:
    """Tests for module-level submit_benchmark_response()."""

    def test_delegates_to_client(self):
        """Module-level submit_benchmark_response() delegates to HaiClient."""
        from jacs import hai
        from jacs.hai import JobResponseResult

        mock_result = JobResponseResult(success=True, job_id="j1", message="ok")

        with patch.object(
            HaiClient, "submit_benchmark_response", return_value=mock_result
        ) as mock_method:
            result = hai.submit_benchmark_response(
                "https://hai.ai",
                job_id="j1",
                message="response",
                metadata={"key": "val"},
                processing_time_ms=100,
                api_key="k",
            )
            assert result.success is True
            mock_method.assert_called_once_with(
                "https://hai.ai", "j1", "response",
                {"key": "val"}, 100, "k",
            )
