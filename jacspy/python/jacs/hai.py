"""
JACS HAI.ai Integration Module

Provides methods for integrating JACS agents with HAI.ai platform:
- register_new_agent(): Create a new JACS agent AND register with HAI.ai in one step
- verify_agent(): Verify another agent's trust level (basic, domain, attested)
- register(): Register an existing agent with HAI.ai
- status(): Check registration status
- testconnection(): Test connectivity to HAI.ai
- benchmark(): Run benchmarks via HAI.ai
- connect(): Connect to HAI.ai SSE stream
- disconnect(): Close SSE connection

Installation:
    # Using uv (recommended)
    uv pip install jacs[hai]

    # Or with pip
    pip install jacs[hai]

Quick Start (recommended for new developers):
    from jacs.hai import register_new_agent

    # Create and register in one step
    result = register_new_agent(
        name="My Trading Bot",
        api_key="your-api-key"  # or set HAI_API_KEY env var
    )
    print(f"Agent registered: {result.agent_id}")
    print(f"Config saved to: ./jacs.config.json")

Verifying Other Agents:
    from jacs.hai import verify_agent

    # Verify another agent meets trust requirements
    result = verify_agent(other_agent_doc, min_level=2)
    if result.valid:
        print(f"Verified: {result.level_name}")  # "basic", "domain", or "attested"

Advanced Usage (existing agents):
    import jacs.simple as jacs
    from jacs.hai import HaiClient

    # Load your existing JACS agent
    jacs.load("./jacs.config.json")

    # Create HAI client
    hai = HaiClient()

    # Test connection
    if hai.testconnection("https://hai.ai"):
        # Register agent
        result = hai.register("https://hai.ai", api_key="your-api-key")
        print(f"Registered: {result}")

Note:
    This module uses a hybrid approach:
    - Rust (via PyO3): Fast sync methods (testconnection, register, status, benchmark)
    - Python (httpx-sse): SSE streaming (connect, disconnect)
    Both implementations are available and work together.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Generator, List, Callable, Union
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


class WebSocketError(HaiError):
    """Error with WebSocket connection.

    Raised when:
    - WebSocket connection fails or is rejected
    - Handshake authentication fails
    - Connection drops unexpectedly
    - Reconnection exhausted
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


@dataclass
class HaiStatusResult:
    """Result of checking agent registration status.

    Attributes:
        registered: Whether the agent is registered with HAI.ai
        agent_id: The agent's JACS ID (if registered)
        registration_id: HAI.ai registration ID (if registered)
        registered_at: When the agent was registered (if registered)
        hai_signatures: List of HAI signature IDs (if registered)
        raw_response: Full API response
    """
    registered: bool
    agent_id: str = ""
    registration_id: str = ""
    registered_at: str = ""
    hai_signatures: List[str] = field(default_factory=list)
    raw_response: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HaiRegistrationPreview:
    """Preview of what would be sent during registration.

    Attributes:
        agent_id: The agent's JACS ID
        agent_name: Human-readable agent name
        payload_json: The full JSON that would be sent (pretty-printed)
        endpoint: The API endpoint that would be called
        headers: Headers that would be sent (API key masked)
    """
    agent_id: str
    agent_name: str
    payload_json: str
    endpoint: str
    headers: Dict[str, str]


@dataclass
class HelloWorldResult:
    """Result of a hello world exchange with HAI.ai.

    Attributes:
        success: Whether the hello world exchange succeeded
        timestamp: ISO 8601 timestamp from HAI's response
        client_ip: The caller's IP address as seen by HAI
        hai_public_key_fingerprint: HAI's public key fingerprint
        message: Human-readable acknowledgment message from HAI
        hai_signature_valid: Whether HAI's signature on the ACK was verified
        raw_response: Full response from the API
    """
    success: bool
    timestamp: str = ""
    client_ip: str = ""
    hai_public_key_fingerprint: str = ""
    message: str = ""
    hai_signature_valid: bool = False
    raw_response: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentVerificationResult:
    """Result of verifying an agent at all trust levels.

    Verification Levels:
        - Level 1 (basic): JACS self-signature valid (cryptographic proof)
        - Level 2 (domain): DNS TXT record verification passed
        - Level 3 (attested): HAI.ai has registered and signed the agent

    Attributes:
        valid: Overall verification passed (meets min_level if specified)
        level: Highest verification level achieved (1, 2, or 3)
        level_name: Human-readable level name ("basic", "domain", "attested")
        agent_id: The verified agent's JACS ID
        jacs_valid: Level 1 - JACS signature is cryptographically valid
        dns_valid: Level 2 - DNS verification passed
        hai_attested: Level 3 - Agent is registered with HAI.ai signatures
        domain: Verified domain (if Level 2+)
        hai_signatures: HAI signature algorithms (if Level 3)
        errors: List of verification errors encountered
        raw_response: Full API response (if HAI verification performed)
    """
    valid: bool
    level: int
    level_name: str
    agent_id: str
    jacs_valid: bool = False
    dns_valid: bool = False
    hai_attested: bool = False
    domain: str = ""
    hai_signatures: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
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
        self._ws_connection: Optional[Any] = None
        self._connected = False
        self._should_disconnect = False
        self._last_event_id: Optional[str] = None  # Sequence tracking for resume

        # Lazy import httpx to avoid dependency issues
        self._httpx = None
        self._httpx_sse = None
        self._websockets = None

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

    def _get_websockets(self):
        """Lazy import websockets library."""
        if self._websockets is None:
            try:
                import websockets.sync.client
                self._websockets = websockets
            except ImportError:
                raise HaiError(
                    "websockets library is required for WebSocket support. "
                    "Install it with: pip install 'jacs[ws]'"
                )
        return self._websockets

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
    # SDK-PY-009: hello_world() method
    # =========================================================================

    def hello_world(
        self,
        hai_url: str,
        include_test: bool = False,
    ) -> HelloWorldResult:
        """Perform a hello world exchange with HAI.ai.

        Sends a JACS-signed request to the HAI hello endpoint. HAI responds
        with a signed ACK containing the caller's IP and a timestamp. This
        verifies end-to-end JACS authentication without requiring a user
        account or API key.

        Args:
            hai_url: Base URL of the HAI.ai server (e.g., "https://hai.ai")
            include_test: If True, request a test scenario preview in the response

        Returns:
            HelloWorldResult with HAI's signed acknowledgment

        Raises:
            HaiConnectionError: If cannot connect to HAI.ai
            AuthenticationError: If JACS signature is rejected
            HaiError: If the exchange fails

        Example:
            import jacs.simple as jacs
            from jacs.hai import HaiClient

            jacs.load("./jacs.config.json")

            hai = HaiClient()
            result = hai.hello_world("https://hai.ai")

            if result.success:
                print(f"HAI says: {result.message}")
                print(f"Your IP: {result.client_ip}")
                print(f"Signature valid: {result.hai_signature_valid}")
        """
        httpx = self._get_httpx()

        # Get agent info for JACS signature auth
        try:
            agent_id = self._get_agent_id()
            agent_json = self._get_agent_json()
        except Exception as e:
            raise HaiError(f"Failed to get agent info: {e}")

        # Build JACS signature auth header
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        sign_payload = f"{agent_id}:{timestamp}"

        try:
            from . import simple as jacs_simple
            signed = jacs_simple.sign_message(sign_payload)
            signature = signed.signature
        except Exception as e:
            raise HaiError(f"Failed to sign hello request: {e}")

        # Build request
        url = self._make_url(hai_url, "/api/v1/agents/hello")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"JACS {agent_id}:{timestamp}:{signature}",
        }
        payload: Dict[str, Any] = {
            "agent_id": agent_id,
        }
        if include_test:
            payload["include_test"] = True

        try:
            logger.info("Sending hello to %s", url)

            response = httpx.post(
                url,
                json=payload,
                headers=headers,
                timeout=self._timeout,
            )

            if response.status_code == 401:
                raise AuthenticationError(
                    "JACS signature rejected by HAI",
                    status_code=response.status_code,
                    response_data=response.json() if response.text else {},
                )

            if response.status_code == 429:
                raise HaiError(
                    "Rate limited -- too many hello requests",
                    status_code=response.status_code,
                )

            if response.status_code not in (200, 201):
                raise HaiError.from_response(
                    response,
                    f"Hello failed with status {response.status_code}",
                )

            data = response.json()

            # Verify HAI's signature on the ACK
            hai_sig_valid = False
            hai_ack_signature = data.get("hai_ack_signature", "")
            if hai_ack_signature:
                hai_sig_valid = self.verify_hai_message(
                    message=json.dumps(data, sort_keys=True),
                    signature=hai_ack_signature,
                    hai_public_key=data.get("hai_public_key", ""),
                )

            logger.info(
                "Hello succeeded: ip=%s, sig_valid=%s",
                data.get("client_ip", ""),
                hai_sig_valid,
            )

            return HelloWorldResult(
                success=True,
                timestamp=data.get("timestamp", ""),
                client_ip=data.get("client_ip", ""),
                hai_public_key_fingerprint=data.get(
                    "hai_public_key_fingerprint", ""
                ),
                message=data.get("message", ""),
                hai_signature_valid=hai_sig_valid,
                raw_response=data,
            )

        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise HaiConnectionError(f"Connection failed: {e}")
        except HaiError:
            raise
        except Exception as e:
            raise HaiError(f"Hello world failed: {e}")

    # =========================================================================
    # SDK-PY-010: verify_hai_message() method
    # =========================================================================

    def verify_hai_message(
        self,
        message: str,
        signature: str,
        hai_public_key: str = "",
    ) -> bool:
        """Verify a message signed by HAI.ai.

        Generic verification function for any HAI-signed message (ACKs,
        attestations, benchmark results, etc.). Uses the HAI public key
        to verify the signature.

        Args:
            message: The message string that was signed
            signature: The signature to verify (base64-encoded)
            hai_public_key: HAI's public key (PEM or base64). If empty,
                attempts to fetch from the loaded agent's trust store.

        Returns:
            True if signature is valid, False otherwise

        Example:
            hai = HaiClient()
            valid = hai.verify_hai_message(
                message='{"status": "ok"}',
                signature="base64sig...",
                hai_public_key="-----BEGIN PUBLIC KEY-----...",
            )
            if valid:
                print("Message is authentically from HAI")
        """
        if not signature:
            logger.warning("verify_hai_message called with empty signature")
            return False

        if not message:
            logger.warning("verify_hai_message called with empty message")
            return False

        # Try to verify using JACS standalone verification if we have
        # a complete signed document structure
        try:
            from . import simple as jacs_simple

            # If the message looks like a JACS signed document, verify directly
            try:
                msg_data = json.loads(message)
                if "jacsSignature" in msg_data:
                    result = jacs_simple.verify(message)
                    return result.valid
            except (json.JSONDecodeError, TypeError):
                pass

            # For raw message + signature pairs, we need the public key
            # to verify. If a HAI public key is provided, attempt
            # cryptographic verification.
            if hai_public_key:
                try:
                    import hashlib
                    import base64

                    # Decode signature
                    try:
                        sig_bytes = base64.b64decode(signature)
                    except Exception:
                        sig_bytes = signature.encode("utf-8")

                    msg_bytes = message.encode("utf-8")

                    # Try Ed25519 verification (most common for HAI)
                    try:
                        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                            Ed25519PublicKey,
                        )
                        from cryptography.hazmat.primitives.serialization import (
                            load_pem_public_key,
                        )

                        if hai_public_key.startswith("-----"):
                            pub_key = load_pem_public_key(
                                hai_public_key.encode("utf-8")
                            )
                        else:
                            key_bytes = base64.b64decode(hai_public_key)
                            pub_key = Ed25519PublicKey.from_public_bytes(
                                key_bytes
                            )

                        pub_key.verify(sig_bytes, msg_bytes)
                        return True
                    except ImportError:
                        logger.debug(
                            "cryptography library not available for "
                            "Ed25519 verification"
                        )
                    except Exception as e:
                        logger.debug("Ed25519 verification failed: %s", e)

                except Exception as e:
                    logger.debug("Raw signature verification failed: %s", e)

        except ImportError:
            logger.debug("jacs.simple not available for verification")

        # If we couldn't verify cryptographically, the signature
        # presence alone is not sufficient
        logger.warning(
            "Could not cryptographically verify HAI message signature"
        )
        return False

    # =========================================================================
    # SDK-PY-001: register() method
    # =========================================================================

    def register(
        self,
        hai_url: str,
        api_key: Optional[str] = None,
        preview: bool = False,
    ) -> Union[HaiRegistrationResult, HaiRegistrationPreview]:
        """Register a JACS agent with HAI.ai.

        Exports the current agent's JSON document and sends it to HAI.ai
        for registration. The agent must be loaded before calling this method.

        Args:
            hai_url: Base URL of the HAI.ai server (e.g., "https://hai.ai")
            api_key: Optional API key for authentication. If not provided,
                     will attempt to use environment variable HAI_API_KEY.
            preview: If True, return a preview of what would be sent without
                     actually registering. Useful for verifying data before submission.

        Returns:
            HaiRegistrationResult if preview=False (default)
            HaiRegistrationPreview if preview=True

        Raises:
            RegistrationError: If registration fails
            HaiConnectionError: If cannot connect to HAI.ai
            AuthenticationError: If API key is invalid

        Example:
            import jacs.simple as jacs
            from jacs.hai import HaiClient

            jacs.load("./jacs.config.json")

            hai = HaiClient()

            # Preview what would be sent
            preview = hai.register("https://hai.ai", api_key="your-key", preview=True)
            print(f"Would send to: {preview.endpoint}")
            print(f"Payload: {preview.payload_json}")

            # Actually register
            result = hai.register("https://hai.ai", api_key="your-key")

            if result.success:
                print(f"Agent {result.agent_id} registered!")
                print(f"HAI signature: {result.hai_signature}")
        """
        import os

        # Get API key from parameter or environment
        if api_key is None:
            api_key = os.environ.get("HAI_API_KEY")

        # Handle preview mode
        if preview:
            # Build the preview without making the actual request
            try:
                agent_json = self._get_agent_json()
                agent_data = json.loads(agent_json)
            except Exception as e:
                raise RegistrationError(f"Failed to export agent: {e}")

            url = self._make_url(hai_url, "/api/v1/agents/register")

            masked_key = f"{api_key[:8]}...{api_key[-4:]}" if api_key and len(api_key) > 12 else "***"

            return HaiRegistrationPreview(
                agent_id=agent_data.get("jacsId", ""),
                agent_name=agent_data.get("name", ""),
                payload_json=json.dumps(agent_data, indent=2),
                endpoint=url,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {masked_key}",
                }
            )

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
    # SDK-PY-004: connect() method for SSE and WebSocket
    # =========================================================================

    def connect(
        self,
        hai_url: str,
        api_key: str,
        on_event: Optional[Callable[[HaiEvent], None]] = None,
        transport: str = "sse",
    ) -> Generator[HaiEvent, None, None]:
        """Connect to HAI.ai event stream via SSE or WebSocket.

        Establishes a connection to HAI.ai for receiving real-time events
        such as jobs, messages, and heartbeats.

        Args:
            hai_url: Base URL of the HAI.ai server
            api_key: API key for authentication
            on_event: Optional callback function for each event
            transport: Transport protocol: "sse" (default) or "ws" (WebSocket)

        Yields:
            HaiEvent objects as they arrive from the stream

        Raises:
            HaiConnectionError: If cannot establish connection
            AuthenticationError: If API key is invalid
            SSEError: If SSE stream encounters an error
            WebSocketError: If WebSocket connection encounters an error
            ValueError: If transport is not "sse" or "ws"

        Example:
            import jacs.simple as jacs
            from jacs.hai import HaiClient

            jacs.load("./jacs.config.json")
            hai = HaiClient()

            # SSE (default)
            for event in hai.connect("https://hai.ai", api_key="..."):
                print(f"Event: {event.event_type}")

            # WebSocket
            for event in hai.connect("https://hai.ai", api_key="...", transport="ws"):
                print(f"Event: {event.event_type}")
        """
        if transport not in ("sse", "ws"):
            raise ValueError(f"transport must be 'sse' or 'ws', got '{transport}'")

        self._should_disconnect = False
        self._connected = False

        if transport == "ws":
            yield from self._ws_connect(hai_url, api_key, on_event)
        else:
            yield from self._sse_connect(hai_url, api_key, on_event)

    def _sse_connect(
        self,
        hai_url: str,
        api_key: str,
        on_event: Optional[Callable[[HaiEvent], None]] = None,
    ) -> Generator[HaiEvent, None, None]:
        """Internal SSE transport implementation."""
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

        reconnect_delay = 1.0
        max_reconnect_delay = 60.0

        while not self._should_disconnect:
            try:
                logger.info("Connecting to SSE stream: %s", url)

                # Include Last-Event-ID for resume if we have one
                request_headers = dict(headers)
                if self._last_event_id:
                    request_headers["Last-Event-ID"] = self._last_event_id

                with httpx.stream("GET", url, headers=request_headers, timeout=None) as response:
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

                        # Track event ID for resume
                        if sse_event.id:
                            self._last_event_id = sse_event.id

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
    # SDK-PY-011: WebSocket transport (Steps 59-60)
    # =========================================================================

    def _ws_connect(
        self,
        hai_url: str,
        api_key: str,
        on_event: Optional[Callable[[HaiEvent], None]] = None,
    ) -> Generator[HaiEvent, None, None]:
        """Internal WebSocket transport implementation.

        Uses JACS-signed handshake as the first message after connection.
        Supports exponential backoff reconnection and sequence number
        tracking for resume.
        """
        ws_mod = self._get_websockets()

        # Get agent info for JACS signature auth
        try:
            agent_id = self._get_agent_id()
        except Exception as e:
            raise HaiConnectionError(f"Failed to get agent ID: {e}")

        # Convert HTTP URL to WS URL
        ws_url = hai_url.replace("https://", "wss://").replace("http://", "ws://")
        ws_url = ws_url.rstrip("/") + f"/api/v1/agents/{agent_id}/ws"

        reconnect_delay = 1.0
        max_reconnect_delay = 60.0

        while not self._should_disconnect:
            try:
                logger.info("Connecting to WebSocket: %s", ws_url)

                ws = ws_mod.sync.client.connect(
                    ws_url,
                    close_timeout=10,
                    open_timeout=self._timeout,
                    additional_headers={
                        "Authorization": f"Bearer {api_key}",
                    },
                )

                try:
                    # Send JACS-signed handshake as first message
                    handshake = self._build_ws_handshake(agent_id)
                    ws.send(json.dumps(handshake))

                    # Wait for handshake ACK
                    ack_raw = ws.recv(timeout=self._timeout)
                    ack_data = json.loads(ack_raw) if isinstance(ack_raw, str) else json.loads(ack_raw.decode())

                    if ack_data.get("type") == "error":
                        error_msg = ack_data.get("message", "Handshake rejected")
                        if ack_data.get("code") == 401:
                            raise AuthenticationError(error_msg, status_code=401)
                        raise WebSocketError(error_msg)

                    self._connected = True
                    self._ws_connection = ws
                    reconnect_delay = 1.0  # Reset on successful connection

                    logger.info("WebSocket connection established")

                    # Yield the connected event
                    yield HaiEvent(
                        event_type="connected",
                        data=ack_data,
                        raw=str(ack_raw),
                    )

                    # Receive loop
                    while not self._should_disconnect:
                        try:
                            raw_msg = ws.recv(timeout=30.0)
                        except TimeoutError:
                            # Send ping to keep alive
                            continue

                        msg_str = raw_msg if isinstance(raw_msg, str) else raw_msg.decode()

                        try:
                            msg_data = json.loads(msg_str)
                        except json.JSONDecodeError:
                            msg_data = msg_str

                        # Extract event metadata
                        event_type = "message"
                        event_id = None
                        if isinstance(msg_data, dict):
                            event_type = msg_data.get("type", msg_data.get("event_type", "message"))
                            event_id = msg_data.get("id", msg_data.get("event_id"))

                        # Track sequence for resume
                        if event_id:
                            self._last_event_id = event_id

                        event = HaiEvent(
                            event_type=event_type,
                            data=msg_data,
                            id=event_id,
                            raw=msg_str,
                        )

                        logger.debug("WS received event: %s", event.event_type)

                        if on_event:
                            on_event(event)

                        yield event

                finally:
                    try:
                        ws.close()
                    except Exception:
                        pass
                    self._ws_connection = None

            except (OSError, ConnectionError) as e:
                self._connected = False

                if self._should_disconnect:
                    break

                logger.warning(
                    "WebSocket connection lost: %s. Reconnecting in %ds...",
                    e, reconnect_delay
                )

                time.sleep(reconnect_delay)
                reconnect_delay = min(reconnect_delay * 2, max_reconnect_delay)

            except HaiError:
                self._connected = False
                raise

            except Exception as e:
                self._connected = False
                raise WebSocketError(f"WebSocket error: {e}")

        self._connected = False
        logger.info("WebSocket connection closed")

    def _build_ws_handshake(self, agent_id: str) -> Dict[str, Any]:
        """Build a JACS-signed handshake message for WS authentication.

        Args:
            agent_id: The agent's JACS ID

        Returns:
            Handshake dict to be JSON-serialized and sent as first WS message
        """
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        sign_payload = f"{agent_id}:{timestamp}"

        try:
            from . import simple as jacs_simple
            signed = jacs_simple.sign_message(sign_payload)
            signature = signed.signature
        except Exception as e:
            raise WebSocketError(f"Failed to sign WS handshake: {e}")

        handshake: Dict[str, Any] = {
            "type": "handshake",
            "agent_id": agent_id,
            "timestamp": timestamp,
            "signature": signature,
        }

        # Include last event ID for resume
        if self._last_event_id:
            handshake["last_event_id"] = self._last_event_id

        return handshake

    # =========================================================================
    # SDK-PY-005: disconnect() method
    # =========================================================================

    def disconnect(self) -> None:
        """Disconnect from HAI.ai event stream (SSE or WebSocket).

        Gracefully closes the connection established by connect().
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
        logger.info("Disconnecting from event stream")
        self._should_disconnect = True

        # Close SSE connection if active
        if self._sse_connection is not None:
            try:
                self._sse_connection.close()
            except Exception as e:
                logger.debug("Error closing SSE connection: %s", e)
            finally:
                self._sse_connection = None

        # Close WebSocket connection if active
        if self._ws_connection is not None:
            try:
                self._ws_connection.close()
            except Exception as e:
                logger.debug("Error closing WebSocket connection: %s", e)
            finally:
                self._ws_connection = None

        self._connected = False

    @property
    def is_connected(self) -> bool:
        """Check if currently connected to SSE stream.

        Returns:
            True if connected, False otherwise
        """
        return self._connected

    # =========================================================================
    # SDK-PY-007: status() method
    # =========================================================================

    def status(
        self,
        hai_url: str,
        api_key: Optional[str] = None,
    ) -> HaiStatusResult:
        """Check registration status of the current agent.

        Queries HAI.ai to determine if the currently loaded JACS agent
        is registered with the platform and retrieves registration details.

        Args:
            hai_url: Base URL of the HAI.ai server (e.g., "https://hai.ai")
            api_key: Optional API key for authentication. If not provided,
                     will attempt to use environment variable HAI_API_KEY.

        Returns:
            HaiStatusResult with registration details

        Raises:
            HaiConnectionError: If cannot connect to HAI.ai
            AuthenticationError: If API key is invalid
            HaiError: If no agent is loaded

        Example:
            import jacs.simple as jacs
            from jacs.hai import HaiClient

            jacs.load("./jacs.config.json")

            hai = HaiClient()
            status = hai.status("https://hai.ai", api_key="your-key")

            if status.registered:
                print(f"Registered since {status.registered_at}")
                print(f"Registration ID: {status.registration_id}")
            else:
                print("Not registered yet")
        """
        import os
        httpx = self._get_httpx()

        # Get API key from parameter or environment
        if api_key is None:
            api_key = os.environ.get("HAI_API_KEY")

        # Get agent ID
        try:
            agent_id = self._get_agent_id()
        except Exception as e:
            raise HaiError(f"Failed to get agent ID: {e}")

        # Build request
        url = self._make_url(hai_url, f"/api/v1/agents/{agent_id}/status")
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # Make request with retries
        last_error = None
        for attempt in range(self._max_retries):
            try:
                logger.debug(
                    "Checking agent status (attempt %d/%d) at %s",
                    attempt + 1, self._max_retries, url
                )

                response = httpx.get(
                    url,
                    headers=headers,
                    timeout=self._timeout,
                )

                # Handle response
                if response.status_code == 200:
                    data = response.json()
                    logger.info("Agent status retrieved: registered=%s", data.get("registered", True))

                    return HaiStatusResult(
                        registered=True,
                        agent_id=data.get("agent_id", data.get("agentId", agent_id)),
                        registration_id=data.get("registration_id", data.get("registrationId", "")),
                        registered_at=data.get("registered_at", data.get("registeredAt", "")),
                        hai_signatures=data.get("hai_signatures", data.get("haiSignatures", [])),
                        raw_response=data,
                    )

                elif response.status_code == 404:
                    # Agent not registered
                    logger.info("Agent %s is not registered", agent_id)
                    return HaiStatusResult(
                        registered=False,
                        agent_id=agent_id,
                        raw_response=response.json() if response.text else {},
                    )

                elif response.status_code == 401:
                    raise AuthenticationError(
                        "Invalid or missing API key",
                        status_code=response.status_code,
                        response_data=response.json() if response.text else {},
                    )

                else:
                    last_error = HaiError.from_response(
                        response,
                        f"Status check failed with status {response.status_code}"
                    )

            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_error = HaiConnectionError(f"Connection failed: {e}")
                logger.warning("Connection failed (attempt %d): %s", attempt + 1, e)

            except HaiError:
                raise

            except Exception as e:
                last_error = HaiError(f"Unexpected error: {e}")
                logger.warning("Unexpected error (attempt %d): %s", attempt + 1, e)

            # Wait before retry (exponential backoff)
            if attempt < self._max_retries - 1:
                time.sleep(2 ** attempt)

        # All retries exhausted
        raise last_error or HaiError("Status check failed after all retries")

    # =========================================================================
    # SDK-PY-008: get_agent_attestation() method - for verifying OTHER agents
    # =========================================================================

    def get_agent_attestation(
        self,
        hai_url: str,
        agent_id: str,
        api_key: Optional[str] = None,
    ) -> HaiStatusResult:
        """Get HAI.ai attestation status for ANY agent by ID.

        Unlike status() which checks the currently loaded agent, this method
        can query the attestation status of any agent by its JACS ID.
        Use this when verifying other agents in agent-to-agent scenarios.

        Args:
            hai_url: Base URL of the HAI.ai server (e.g., "https://hai.ai")
            agent_id: The JACS agent ID to check
            api_key: Optional API key for authentication

        Returns:
            HaiStatusResult with registration and attestation details

        Example:
            from jacs.hai import HaiClient

            hai = HaiClient()
            # Check if another agent is HAI-attested
            result = hai.get_agent_attestation("https://hai.ai", "other-agent-id")
            if result.registered and result.hai_signatures:
                print("Agent is HAI-attested (Level 3)")
        """
        import os
        httpx = self._get_httpx()

        # Get API key from parameter or environment
        if api_key is None:
            api_key = os.environ.get("HAI_API_KEY")

        # Build request
        url = self._make_url(hai_url, f"/api/v1/agents/{agent_id}/status")
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        try:
            response = httpx.get(url, headers=headers, timeout=self._timeout)

            if response.status_code == 200:
                data = response.json()
                return HaiStatusResult(
                    registered=True,
                    agent_id=data.get("agent_id", data.get("agentId", agent_id)),
                    registration_id=data.get("registration_id", data.get("registrationId", "")),
                    registered_at=data.get("registered_at", data.get("registeredAt", "")),
                    hai_signatures=data.get("hai_signatures", data.get("haiSignatures", [])),
                    raw_response=data,
                )
            elif response.status_code == 404:
                return HaiStatusResult(
                    registered=False,
                    agent_id=agent_id,
                    raw_response=response.json() if response.text else {},
                )
            else:
                raise HaiError(
                    f"Failed to get attestation: HTTP {response.status_code}",
                    status_code=response.status_code,
                )
        except Exception as e:
            if isinstance(e, HaiError):
                raise
            raise HaiError(f"Failed to get attestation: {e}")


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


def hello_world(
    hai_url: str,
    include_test: bool = False,
) -> HelloWorldResult:
    """Perform a hello world exchange with HAI.ai.

    See HaiClient.hello_world() for full documentation.
    """
    return _get_client().hello_world(hai_url, include_test)


def register(
    hai_url: str,
    api_key: Optional[str] = None,
    preview: bool = False,
) -> Union[HaiRegistrationResult, HaiRegistrationPreview]:
    """Register a JACS agent with HAI.ai.

    See HaiClient.register() for full documentation.
    """
    return _get_client().register(hai_url, api_key, preview)


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
    transport: str = "sse",
) -> Generator[HaiEvent, None, None]:
    """Connect to HAI.ai event stream via SSE or WebSocket.

    See HaiClient.connect() for full documentation.
    """
    return _get_client().connect(hai_url, api_key, on_event, transport)


def disconnect() -> None:
    """Disconnect from HAI.ai SSE stream.

    See HaiClient.disconnect() for full documentation.
    """
    return _get_client().disconnect()


def status(hai_url: str, api_key: Optional[str] = None) -> HaiStatusResult:
    """Check registration status of the current agent.

    See HaiClient.status() for full documentation.
    """
    return _get_client().status(hai_url, api_key)


def register_new_agent(
    name: str,
    hai_url: str = "https://hai.ai",
    api_key: Optional[str] = None,
    key_algorithm: str = "ed25519",
    output_dir: str = ".",
) -> HaiRegistrationResult:
    """Create a new JACS agent and register it with HAI.ai in one step.

    This is the fastest way to get started with HAI.ai. It:
    1. Creates a new JACS agent with cryptographic keys
    2. Registers the agent with HAI.ai
    3. Returns the registration result with HAI's signature

    Args:
        name: Human-readable name for your agent (e.g., "My Trading Bot")
        hai_url: HAI.ai server URL (default: "https://hai.ai")
        api_key: API key for HAI.ai. If not provided, uses HAI_API_KEY env var.
        key_algorithm: Cryptographic algorithm ("ed25519" or "pq2025")
        output_dir: Directory to save agent config files (default: current dir)

    Returns:
        HaiRegistrationResult with agent_id, hai_signature, and registration details

    Raises:
        RegistrationError: If registration fails
        HaiConnectionError: If cannot connect to HAI.ai

    Example:
        from jacs.hai import register_new_agent

        result = register_new_agent(
            name="My Trading Bot",
            api_key="your-api-key"  # or set HAI_API_KEY env var
        )
        print(f"Agent registered: {result.agent_id}")
        print(f"Config saved to: ./jacs.config.json")
    """
    import os
    from contextlib import contextmanager
    from . import simple as jacs_simple

    @contextmanager
    def _change_dir(path: str):
        """Context manager for safe directory changes."""
        original_dir = os.getcwd()
        try:
            os.chdir(path)
            yield
        finally:
            os.chdir(original_dir)

    # Step 1: Create the JACS agent
    try:
        with _change_dir(output_dir):
            jacs_simple.create(
                name=name,
                algorithm=key_algorithm,
            )
    except Exception as e:
        raise RegistrationError(f"Failed to create JACS agent: {e}")

    # Step 2: Load the newly created agent
    config_path = os.path.join(output_dir, "jacs.config.json")
    try:
        jacs_simple.load(config_path)
    except Exception as e:
        raise RegistrationError(f"Failed to load created agent: {e}")

    # Step 3: Register with HAI.ai
    client = HaiClient()
    return client.register(hai_url, api_key)


def verify_agent(
    agent_document: Union[str, dict],
    min_level: int = 1,
    require_domain: Optional[str] = None,
    hai_url: str = "https://hai.ai",
) -> AgentVerificationResult:
    """Verify another agent's trust level.

    Use this function to verify the identity and trust level of an agent
    before accepting their messages, agreements, or transactions.

    Verification Levels:
        - Level 1 (basic): JACS self-signature valid (cryptographic proof)
        - Level 2 (domain): DNS TXT record verification passed
        - Level 3 (attested): HAI.ai has registered and signed the agent

    Args:
        agent_document: The agent's JACS document (JSON string or dict)
        min_level: Minimum required verification level (1, 2, or 3)
        require_domain: If specified, require the agent to be verified for this domain
        hai_url: HAI.ai server URL (default: "https://hai.ai")

    Returns:
        AgentVerificationResult with verification status at all levels

    Raises:
        HaiError: If verification request fails

    Example:
        from jacs.hai import verify_agent

        # Verify another agent meets your trust requirements
        result = verify_agent(sender_agent_doc, min_level=2)

        if result.valid:
            print(f"Verified agent {result.agent_id} at level {result.level}")
        else:
            print(f"Verification failed: {result.errors}")
    """
    from . import simple as jacs_simple

    errors: List[str] = []
    agent_id = ""
    jacs_valid = False
    dns_valid = False
    hai_attested = False
    domain = ""
    hai_signatures: List[str] = []
    raw_response: Dict[str, Any] = {}

    # Convert to string if dict
    if isinstance(agent_document, dict):
        agent_document = json.dumps(agent_document)

    # Level 1: JACS signature verification (local)
    try:
        result = jacs_simple.verify(agent_document)
        jacs_valid = result.valid
        agent_id = result.signer_id or ""
        if not jacs_valid:
            errors.extend(result.errors or ["JACS signature invalid"])
    except Exception as e:
        errors.append(f"JACS verification error: {e}")

    # Level 2: DNS verification (if domain provided or extractable)
    # Try to extract domain from agent document
    try:
        doc = json.loads(agent_document) if isinstance(agent_document, str) else agent_document
        domain = doc.get("jacsDomain", "") or require_domain or ""
    except (json.JSONDecodeError, KeyError, TypeError):
        pass

    if domain and jacs_valid:
        try:
            # DNS verification via JACS
            dns_result = jacs_simple.verify_dns(agent_document, domain)
            dns_valid = dns_result if isinstance(dns_result, bool) else getattr(dns_result, 'valid', False)
        except AttributeError:
            # verify_dns may not exist yet
            pass
        except Exception as e:
            errors.append(f"DNS verification error: {e}")

    # Level 3: HAI.ai attestation
    if jacs_valid and agent_id:
        try:
            client = HaiClient()
            # Query status for the OTHER agent by ID
            attestation = client.get_agent_attestation(hai_url, agent_id)
            hai_attested = attestation.registered and len(attestation.hai_signatures) > 0
            if hai_attested:
                hai_signatures = attestation.hai_signatures
            raw_response = attestation.raw_response
        except Exception as e:
            errors.append(f"HAI verification error: {e}")

    # Compute level
    if hai_attested and dns_valid and jacs_valid:
        level = 3
        level_name = "attested"
    elif dns_valid and jacs_valid:
        level = 2
        level_name = "domain"
    elif jacs_valid:
        level = 1
        level_name = "basic"
    else:
        level = 0
        level_name = "none"

    # Check minimum level requirement
    valid = level >= min_level

    # Check domain requirement
    if require_domain and domain != require_domain:
        valid = False
        errors.append(f"Domain mismatch: expected {require_domain}, got {domain}")

    return AgentVerificationResult(
        valid=valid,
        level=level,
        level_name=level_name,
        agent_id=agent_id,
        jacs_valid=jacs_valid,
        dns_valid=dns_valid,
        hai_attested=hai_attested,
        domain=domain,
        hai_signatures=hai_signatures,
        errors=errors,
        raw_response=raw_response,
    )


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
    "WebSocketError",
    # Data types
    "HaiRegistrationResult",
    "HaiRegistrationPreview",
    "HaiStatusResult",
    "HaiEvent",
    "BenchmarkResult",
    "AgentVerificationResult",
    "HelloWorldResult",
    # Convenience functions
    "testconnection",
    "hello_world",
    "register",
    "register_new_agent",
    "verify_agent",
    "status",
    "benchmark",
    "connect",
    "disconnect",
]
