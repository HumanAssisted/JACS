"""
JACS HAI.ai Integration Module

Provides methods for integrating JACS agents with HAI.ai platform:
- register(): Register an agent with HAI.ai
- testconnection(): Test connectivity to HAI.ai
- benchmark(): Run benchmarks via HAI.ai
- connect(): Connect to HAI.ai SSE stream
- disconnect(): Close SSE connection

Example:
    import jacs.simple as jacs
    from jacs.hai import HaiClient

    # Load your JACS agent
    jacs.load("./jacs.config.json")

    # Create HAI client
    hai = HaiClient()

    # Test connection
    if hai.testconnection("https://hai.ai"):
        # Register agent
        result = hai.register("https://hai.ai", api_key="your-api-key")
        print(f"Registered: {result}")
"""

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Generator, List, Callable
from urllib.parse import urljoin

# Configure module logger
logger = logging.getLogger("jacs.hai")


# =============================================================================
# SDK-PY-006: Error Handling Classes
# =============================================================================

class HaiError(Exception):
    """Base exception for HAI.ai integration errors.

    All HAI-specific errors inherit from this class, making it easy to catch
    any HAI-related exception.

    Attributes:
        message: Human-readable error description
        status_code: HTTP status code if available
        response_data: Raw response data from the API if available
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_data: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_data = response_data or {}

    def __str__(self) -> str:
        if self.status_code:
            return f"{self.message} (HTTP {self.status_code})"
        return self.message

    @classmethod
    def from_response(cls, response: Any, default_message: str = "HAI.ai API error") -> "HaiError":
        """Create an error from an HTTP response object.

        Args:
            response: HTTP response object (e.g., from httpx)
            default_message: Message to use if response has no error details

        Returns:
            Appropriate HaiError subclass based on status code
        """
        try:
            data = response.json()
            message = data.get("error", data.get("message", default_message))
        except (ValueError, AttributeError):
            message = default_message
            data = {}

        status_code = getattr(response, "status_code", None)

        # Return appropriate subclass based on context
        return cls(message, status_code, data)


class RegistrationError(HaiError):
    """Error during agent registration with HAI.ai.

    Raised when:
    - Agent document is invalid
    - Registration endpoint returns an error
    - Agent is already registered
    - Authentication fails
    """
    pass


class HaiConnectionError(HaiError):
    """Error connecting to HAI.ai.

    Raised when:
    - HAI.ai server is unreachable
    - SSL/TLS errors occur
    - Connection timeout
    - Network errors

    Note: Named HaiConnectionError to avoid conflict with built-in ConnectionError.
    """
    pass


class BenchmarkError(HaiError):
    """Error during benchmark execution.

    Raised when:
    - Benchmark suite not found
    - Benchmark job fails
    - Timeout waiting for results
    - Agent fails to complete benchmark tasks
    """
    pass


class AuthenticationError(HaiError):
    """Error with API authentication.

    Raised when:
    - API key is invalid
    - API key is expired
    - Insufficient permissions
    """
    pass


class SSEError(HaiError):
    """Error with Server-Sent Events connection.

    Raised when:
    - SSE stream disconnects unexpectedly
    - Invalid event format received
    - Reconnection fails
    """
    pass


# =============================================================================
# Data Types
# =============================================================================

@dataclass
class HaiRegistrationResult:
    """Result of registering an agent with HAI.ai.

    Attributes:
        success: Whether registration was successful
        agent_id: The registered agent's ID
        hai_signature: HAI.ai's signature on the registration
        registration_id: Unique ID for this registration
        registered_at: ISO 8601 timestamp of registration
        capabilities: List of capabilities recognized by HAI.ai
        raw_response: Full response from the API
    """
    success: bool
    agent_id: str
    hai_signature: str = ""
    registration_id: str = ""
    registered_at: str = ""
    capabilities: List[str] = field(default_factory=list)
    raw_response: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HaiEvent:
    """An event received from HAI.ai SSE stream.

    Attributes:
        event_type: Type of event (e.g., "job", "heartbeat", "message")
        data: Event payload as parsed JSON
        id: Event ID if provided
        retry: Retry interval in milliseconds if provided
        raw: Raw event data string
    """
    event_type: str
    data: Any
    id: Optional[str] = None
    retry: Optional[int] = None
    raw: str = ""


@dataclass
class BenchmarkResult:
    """Result of running a benchmark suite.

    Attributes:
        success: Whether the benchmark completed successfully
        suite: Name of the benchmark suite
        score: Overall benchmark score (0-100)
        passed: Number of tests passed
        failed: Number of tests failed
        total: Total number of tests
        duration_ms: Total duration in milliseconds
        results: Detailed results per test
        raw_response: Full response from the API
    """
    success: bool
    suite: str
    score: float = 0.0
    passed: int = 0
    failed: int = 0
    total: int = 0
    duration_ms: int = 0
    results: List[Dict[str, Any]] = field(default_factory=list)
    raw_response: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# HAI Client Implementation
# =============================================================================

class HaiClient:
    """Client for interacting with HAI.ai platform.

    This client provides methods for:
    - Registering JACS agents with HAI.ai
    - Testing connectivity
    - Running benchmarks
    - Connecting to SSE event streams

    Example:
        from jacs.hai import HaiClient
        import jacs.simple as jacs

        # Load agent first
        jacs.load("./jacs.config.json")

        # Create client
        hai = HaiClient()

        # Test connection
        if hai.testconnection("https://hai.ai"):
            result = hai.register("https://hai.ai", api_key="...")
            print(f"Registered: {result.agent_id}")
    """

    def __init__(self, timeout: float = 30.0, max_retries: int = 3):
        """Initialize the HAI client.

        Args:
            timeout: Default timeout for HTTP requests in seconds
            max_retries: Maximum number of retry attempts for failed requests
        """
        self._timeout = timeout
        self._max_retries = max_retries
        self._sse_connection: Optional[Any] = None
        self._connected = False
        self._should_disconnect = False

        # Lazy import httpx to avoid dependency issues
        self._httpx = None
        self._httpx_sse = None

    def _get_httpx(self):
        """Lazy import httpx library."""
        if self._httpx is None:
            try:
                import httpx
                self._httpx = httpx
            except ImportError:
                raise HaiError(
                    "httpx library is required for HAI.ai integration. "
                    "Install it with: pip install httpx"
                )
        return self._httpx

    def _get_httpx_sse(self):
        """Lazy import httpx-sse library."""
        if self._httpx_sse is None:
            try:
                import httpx_sse
                self._httpx_sse = httpx_sse
            except ImportError:
                raise HaiError(
                    "httpx-sse library is required for SSE support. "
                    "Install it with: pip install httpx-sse"
                )
        return self._httpx_sse

    def _get_agent_json(self) -> str:
        """Get the current agent's JSON document.

        Returns:
            Agent document as JSON string

        Raises:
            HaiError: If no agent is loaded
        """
        try:
            from . import simple as jacs_simple
            if not jacs_simple.is_loaded():
                raise HaiError(
                    "No JACS agent loaded. Call jacs.load() first."
                )
            return jacs_simple.export_agent()
        except ImportError:
            raise HaiError("Failed to import jacs.simple module")

    def _get_agent_id(self) -> str:
        """Get the current agent's ID.

        Returns:
            Agent ID string

        Raises:
            HaiError: If no agent is loaded
        """
        try:
            from . import simple as jacs_simple
            if not jacs_simple.is_loaded():
                raise HaiError(
                    "No JACS agent loaded. Call jacs.load() first."
                )
            info = jacs_simple.get_agent_info()
            return info.agent_id if info else ""
        except ImportError:
            raise HaiError("Failed to import jacs.simple module")

    def _make_url(self, base_url: str, path: str) -> str:
        """Construct a full URL from base and path.

        Args:
            base_url: Base URL (e.g., "https://hai.ai")
            path: API path (e.g., "/api/v1/agents/register")

        Returns:
            Full URL string
        """
        # Ensure base URL doesn't end with slash
        base = base_url.rstrip("/")
        # Ensure path starts with slash
        path = "/" + path.lstrip("/")
        return base + path

    # =========================================================================
    # SDK-PY-002: testconnection() method
    # =========================================================================

    def testconnection(self, hai_url: str) -> bool:
        """Test connectivity to HAI.ai server.

        Attempts to connect to the HAI.ai health endpoint to verify
        the server is reachable and responding.

        Args:
            hai_url: Base URL of the HAI.ai server (e.g., "https://hai.ai")

        Returns:
            True if connection successful, False otherwise

        Example:
            hai = HaiClient()
            if hai.testconnection("https://hai.ai"):
                print("HAI.ai is reachable!")
            else:
                print("Cannot connect to HAI.ai")
        """
        httpx = self._get_httpx()

        # Try multiple health endpoints
        health_endpoints = [
            "/api/v1/health",
            "/health",
            "/api/health",
            "/",
        ]

        for endpoint in health_endpoints:
            try:
                url = self._make_url(hai_url, endpoint)
                logger.debug("Testing connection to %s", url)

                response = httpx.get(
                    url,
                    timeout=min(self._timeout, 10.0),  # Use shorter timeout for health check
                    follow_redirects=True,
                )

                # Consider 2xx status codes as success
                if 200 <= response.status_code < 300:
                    logger.info("Connection successful to %s", url)
                    return True

            except Exception as e:
                logger.debug("Connection failed to %s: %s", endpoint, e)
                continue

        logger.warning("All connection attempts to %s failed", hai_url)
        return False

    # =========================================================================
    # SDK-PY-001: register() method
    # =========================================================================

    def register(
        self,
        hai_url: str,
        api_key: Optional[str] = None,
    ) -> HaiRegistrationResult:
        """Register a JACS agent with HAI.ai.

        Exports the current agent's JSON document and sends it to HAI.ai
        for registration. The agent must be loaded before calling this method.

        Args:
            hai_url: Base URL of the HAI.ai server (e.g., "https://hai.ai")
            api_key: Optional API key for authentication. If not provided,
                     will attempt to use environment variable HAI_API_KEY.

        Returns:
            HaiRegistrationResult with registration details and HAI signature

        Raises:
            RegistrationError: If registration fails
            HaiConnectionError: If cannot connect to HAI.ai
            AuthenticationError: If API key is invalid

        Example:
            import jacs.simple as jacs
            from jacs.hai import HaiClient

            jacs.load("./jacs.config.json")

            hai = HaiClient()
            result = hai.register("https://hai.ai", api_key="your-key")

            if result.success:
                print(f"Agent {result.agent_id} registered!")
                print(f"HAI signature: {result.hai_signature}")
        """
        import os
        httpx = self._get_httpx()

        # Get API key from parameter or environment
        if api_key is None:
            api_key = os.environ.get("HAI_API_KEY")

        # Get agent JSON
        try:
            agent_json = self._get_agent_json()
            agent_data = json.loads(agent_json)
        except Exception as e:
            raise RegistrationError(f"Failed to export agent: {e}")

        # Build request
        url = self._make_url(hai_url, "/api/v1/agents/register")
        headers = {
            "Content-Type": "application/json",
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # Make request with retries
        last_error = None
        for attempt in range(self._max_retries):
            try:
                logger.debug(
                    "Registering agent (attempt %d/%d) to %s",
                    attempt + 1, self._max_retries, url
                )

                response = httpx.post(
                    url,
                    json=agent_data,
                    headers=headers,
                    timeout=self._timeout,
                )

                # Handle response
                if response.status_code == 200 or response.status_code == 201:
                    data = response.json()
                    logger.info("Agent registered successfully: %s", data.get("agent_id", ""))

                    return HaiRegistrationResult(
                        success=True,
                        agent_id=data.get("agent_id", data.get("agentId", "")),
                        hai_signature=data.get("hai_signature", data.get("haiSignature", "")),
                        registration_id=data.get("registration_id", data.get("registrationId", "")),
                        registered_at=data.get("registered_at", data.get("registeredAt", "")),
                        capabilities=data.get("capabilities", []),
                        raw_response=data,
                    )

                elif response.status_code == 401:
                    raise AuthenticationError(
                        "Invalid or missing API key",
                        status_code=response.status_code,
                        response_data=response.json() if response.text else {},
                    )

                elif response.status_code == 409:
                    # Agent already registered
                    data = response.json() if response.text else {}
                    raise RegistrationError(
                        "Agent is already registered",
                        status_code=response.status_code,
                        response_data=data,
                    )

                else:
                    last_error = RegistrationError.from_response(
                        response,
                        f"Registration failed with status {response.status_code}"
                    )

            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_error = HaiConnectionError(f"Connection failed: {e}")
                logger.warning("Connection failed (attempt %d): %s", attempt + 1, e)

            except HaiError:
                raise

            except Exception as e:
                last_error = RegistrationError(f"Unexpected error: {e}")
                logger.warning("Unexpected error (attempt %d): %s", attempt + 1, e)

            # Wait before retry (exponential backoff)
            if attempt < self._max_retries - 1:
                time.sleep(2 ** attempt)

        # All retries exhausted
        raise last_error or RegistrationError("Registration failed after all retries")

    # =========================================================================
    # SDK-PY-003: benchmark() method
    # =========================================================================

    def benchmark(
        self,
        hai_url: str,
        api_key: str,
        suite: str = "mediator",
        timeout: Optional[float] = None,
    ) -> BenchmarkResult:
        """Run a benchmark suite via HAI.ai.

        Connects to HAI.ai and requests execution of a benchmark suite.
        The benchmark may be run via SSE stream or REST API depending
        on the HAI.ai implementation.

        Args:
            hai_url: Base URL of the HAI.ai server
            api_key: API key for authentication
            suite: Benchmark suite name (default: "mediator")
            timeout: Optional timeout override for benchmark execution

        Returns:
            BenchmarkResult with scores and detailed test results

        Raises:
            BenchmarkError: If benchmark execution fails
            HaiConnectionError: If cannot connect to HAI.ai
            AuthenticationError: If API key is invalid

        Example:
            import jacs.simple as jacs
            from jacs.hai import HaiClient

            jacs.load("./jacs.config.json")

            hai = HaiClient()
            result = hai.benchmark(
                "https://hai.ai",
                api_key="your-key",
                suite="mediator"
            )

            print(f"Score: {result.score}")
            print(f"Passed: {result.passed}/{result.total}")
        """
        httpx = self._get_httpx()

        # Get agent ID
        try:
            agent_id = self._get_agent_id()
        except Exception as e:
            raise BenchmarkError(f"Failed to get agent ID: {e}")

        # Build request
        url = self._make_url(hai_url, "/api/benchmark/run")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        payload = {
            "agent_id": agent_id,
            "suite": suite,
        }

        # Use longer timeout for benchmarks
        request_timeout = timeout or max(self._timeout, 120.0)

        try:
            logger.info("Starting benchmark suite '%s' for agent %s", suite, agent_id)

            response = httpx.post(
                url,
                json=payload,
                headers=headers,
                timeout=request_timeout,
            )

            if response.status_code == 401:
                raise AuthenticationError(
                    "Invalid or missing API key",
                    status_code=response.status_code,
                )

            if response.status_code != 200:
                raise BenchmarkError.from_response(
                    response,
                    f"Benchmark request failed with status {response.status_code}"
                )

            data = response.json()

            # Check if this is an async job (need to poll for results)
            if data.get("job_id") or data.get("jobId"):
                job_id = data.get("job_id") or data.get("jobId")
                return self._poll_benchmark_result(hai_url, api_key, job_id, request_timeout)

            # Synchronous result
            logger.info("Benchmark completed: score=%s", data.get("score", 0))

            return BenchmarkResult(
                success=data.get("success", True),
                suite=suite,
                score=float(data.get("score", 0)),
                passed=int(data.get("passed", 0)),
                failed=int(data.get("failed", 0)),
                total=int(data.get("total", 0)),
                duration_ms=int(data.get("duration_ms", data.get("durationMs", 0))),
                results=data.get("results", []),
                raw_response=data,
            )

        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise HaiConnectionError(f"Connection failed: {e}")
        except HaiError:
            raise
        except Exception as e:
            raise BenchmarkError(f"Benchmark execution failed: {e}")

    def _poll_benchmark_result(
        self,
        hai_url: str,
        api_key: str,
        job_id: str,
        timeout: float,
    ) -> BenchmarkResult:
        """Poll for async benchmark result.

        Args:
            hai_url: Base URL of the HAI.ai server
            api_key: API key for authentication
            job_id: Benchmark job ID to poll
            timeout: Maximum time to wait for result

        Returns:
            BenchmarkResult when job completes

        Raises:
            BenchmarkError: If job fails or times out
        """
        httpx = self._get_httpx()

        url = self._make_url(hai_url, f"/api/benchmark/jobs/{job_id}")
        headers = {"Authorization": f"Bearer {api_key}"}

        start_time = time.time()
        poll_interval = 2.0

        while (time.time() - start_time) < timeout:
            try:
                response = httpx.get(url, headers=headers, timeout=30.0)

                if response.status_code != 200:
                    raise BenchmarkError.from_response(response)

                data = response.json()
                status = data.get("status", "").lower()

                if status == "completed":
                    return BenchmarkResult(
                        success=True,
                        suite=data.get("suite", ""),
                        score=float(data.get("score", 0)),
                        passed=int(data.get("passed", 0)),
                        failed=int(data.get("failed", 0)),
                        total=int(data.get("total", 0)),
                        duration_ms=int(data.get("duration_ms", 0)),
                        results=data.get("results", []),
                        raw_response=data,
                    )

                elif status in ("failed", "error"):
                    raise BenchmarkError(
                        data.get("error", "Benchmark job failed"),
                        response_data=data,
                    )

                # Still running, wait and poll again
                time.sleep(poll_interval)
                poll_interval = min(poll_interval * 1.5, 10.0)  # Exponential backoff

            except HaiError:
                raise
            except Exception as e:
                raise BenchmarkError(f"Failed to poll benchmark status: {e}")

        raise BenchmarkError(f"Benchmark timed out after {timeout} seconds")

    # =========================================================================
    # SDK-PY-004: connect() method for SSE
    # =========================================================================

    def connect(
        self,
        hai_url: str,
        api_key: str,
        on_event: Optional[Callable[[HaiEvent], None]] = None,
    ) -> Generator[HaiEvent, None, None]:
        """Connect to HAI.ai SSE event stream.

        Establishes a Server-Sent Events connection to HAI.ai for receiving
        real-time events such as jobs, messages, and heartbeats.

        Args:
            hai_url: Base URL of the HAI.ai server
            api_key: API key for authentication
            on_event: Optional callback function for each event

        Yields:
            HaiEvent objects as they arrive from the stream

        Raises:
            HaiConnectionError: If cannot establish SSE connection
            AuthenticationError: If API key is invalid
            SSEError: If stream encounters an error

        Example:
            import jacs.simple as jacs
            from jacs.hai import HaiClient

            jacs.load("./jacs.config.json")
            hai = HaiClient()

            # Generator style
            for event in hai.connect("https://hai.ai", api_key="..."):
                print(f"Event: {event.event_type}")
                if event.event_type == "job":
                    process_job(event.data)

            # Or with callback
            def handle_event(event):
                print(f"Received: {event.event_type}")

            for event in hai.connect("https://hai.ai", "...", on_event=handle_event):
                pass  # Callback handles events
        """
        httpx = self._get_httpx()
        httpx_sse = self._get_httpx_sse()

        # Get agent ID
        try:
            agent_id = self._get_agent_id()
        except Exception as e:
            raise HaiConnectionError(f"Failed to get agent ID: {e}")

        url = self._make_url(hai_url, f"/api/v1/agents/{agent_id}/events")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "text/event-stream",
        }

        self._should_disconnect = False
        self._connected = False
        reconnect_delay = 1.0
        max_reconnect_delay = 60.0

        while not self._should_disconnect:
            try:
                logger.info("Connecting to SSE stream: %s", url)

                with httpx.stream("GET", url, headers=headers, timeout=None) as response:
                    if response.status_code == 401:
                        raise AuthenticationError(
                            "Invalid or missing API key",
                            status_code=response.status_code,
                        )

                    if response.status_code != 200:
                        raise HaiConnectionError(
                            f"SSE connection failed with status {response.status_code}",
                            status_code=response.status_code,
                        )

                    self._connected = True
                    self._sse_connection = response
                    reconnect_delay = 1.0  # Reset on successful connection

                    logger.info("SSE connection established")

                    # Process SSE events
                    for sse_event in httpx_sse.EventSource(response).iter_sse():
                        if self._should_disconnect:
                            break

                        # Parse event data
                        try:
                            data = json.loads(sse_event.data) if sse_event.data else {}
                        except json.JSONDecodeError:
                            data = sse_event.data

                        event = HaiEvent(
                            event_type=sse_event.event or "message",
                            data=data,
                            id=sse_event.id,
                            retry=sse_event.retry,
                            raw=sse_event.data or "",
                        )

                        logger.debug("Received event: %s", event.event_type)

                        # Call callback if provided
                        if on_event:
                            on_event(event)

                        yield event

            except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadError) as e:
                self._connected = False

                if self._should_disconnect:
                    break

                logger.warning(
                    "SSE connection lost: %s. Reconnecting in %ds...",
                    e, reconnect_delay
                )

                time.sleep(reconnect_delay)
                reconnect_delay = min(reconnect_delay * 2, max_reconnect_delay)

            except HaiError:
                self._connected = False
                raise

            except Exception as e:
                self._connected = False
                raise SSEError(f"SSE stream error: {e}")

        self._connected = False
        logger.info("SSE connection closed")

    # =========================================================================
    # SDK-PY-005: disconnect() method
    # =========================================================================

    def disconnect(self) -> None:
        """Disconnect from HAI.ai SSE stream.

        Gracefully closes the SSE connection established by connect().
        Safe to call even if not connected.

        Example:
            hai = HaiClient()

            # Start connection in a thread
            import threading

            def receive_events():
                for event in hai.connect("https://hai.ai", api_key="..."):
                    print(event.event_type)

            thread = threading.Thread(target=receive_events)
            thread.start()

            # Later, disconnect
            time.sleep(60)
            hai.disconnect()
            thread.join()
        """
        logger.info("Disconnecting from SSE stream")
        self._should_disconnect = True

        # Close the connection if active
        if self._sse_connection is not None:
            try:
                self._sse_connection.close()
            except Exception as e:
                logger.debug("Error closing SSE connection: %s", e)
            finally:
                self._sse_connection = None

        self._connected = False

    @property
    def is_connected(self) -> bool:
        """Check if currently connected to SSE stream.

        Returns:
            True if connected, False otherwise
        """
        return self._connected


# =============================================================================
# Module-level convenience functions
# =============================================================================

# Global client instance for convenience
_client: Optional[HaiClient] = None


def _get_client() -> HaiClient:
    """Get or create the global HAI client."""
    global _client
    if _client is None:
        _client = HaiClient()
    return _client


def testconnection(hai_url: str) -> bool:
    """Test connectivity to HAI.ai server.

    See HaiClient.testconnection() for full documentation.
    """
    return _get_client().testconnection(hai_url)


def register(hai_url: str, api_key: Optional[str] = None) -> HaiRegistrationResult:
    """Register a JACS agent with HAI.ai.

    See HaiClient.register() for full documentation.
    """
    return _get_client().register(hai_url, api_key)


def benchmark(
    hai_url: str,
    api_key: str,
    suite: str = "mediator",
) -> BenchmarkResult:
    """Run a benchmark suite via HAI.ai.

    See HaiClient.benchmark() for full documentation.
    """
    return _get_client().benchmark(hai_url, api_key, suite)


def connect(
    hai_url: str,
    api_key: str,
    on_event: Optional[Callable[[HaiEvent], None]] = None,
) -> Generator[HaiEvent, None, None]:
    """Connect to HAI.ai SSE event stream.

    See HaiClient.connect() for full documentation.
    """
    return _get_client().connect(hai_url, api_key, on_event)


def disconnect() -> None:
    """Disconnect from HAI.ai SSE stream.

    See HaiClient.disconnect() for full documentation.
    """
    return _get_client().disconnect()


__all__ = [
    # Client class
    "HaiClient",
    # Error types
    "HaiError",
    "RegistrationError",
    "HaiConnectionError",
    "BenchmarkError",
    "AuthenticationError",
    "SSEError",
    # Data types
    "HaiRegistrationResult",
    "HaiEvent",
    "BenchmarkResult",
    # Convenience functions
    "testconnection",
    "register",
    "benchmark",
    "connect",
    "disconnect",
]
