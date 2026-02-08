//! HAI client for interacting with HAI.ai
//!
//! This module provides a complete, clean API for connecting to HAI services:
//!
//! ## Construction
//! - `HaiClient::new()` - create client with endpoint URL
//! - `with_api_key()` - set API key for authentication
//!
//! ## Core Methods
//! - `testconnection()` - verify connectivity to the HAI server
//! - `register()` - register a JACS agent with HAI
//! - `status()` - check registration status of an agent
//! - `benchmark()` - run a benchmark suite on an agent
//!
//! ## SSE Streaming
//! - `connect()` / `disconnect()` - SSE event streaming for real-time updates
//! - `is_connected()` / `connection_state()` - check connection status
//!
//! # Example
//!
//! ```rust,ignore
//! use jacs_binding_core::hai::{HaiClient, HaiError, HaiEvent};
//! use jacs_binding_core::AgentWrapper;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), HaiError> {
//!     let client = HaiClient::new("https://api.hai.ai")
//!         .with_api_key("your-api-key");
//!
//!     // Test connectivity
//!     if client.testconnection().await? {
//!         println!("Connected to HAI");
//!     }
//!
//!     // Register an agent
//!     let agent = AgentWrapper::new();
//!     agent.load("/path/to/config.json".to_string()).unwrap();
//!     let result = client.register(&agent).await?;
//!     println!("Registered: {}", result.agent_id);
//!
//!     // Connect to SSE stream and handle events
//!     let mut receiver = client.connect().await?;
//!     while let Some(event) = receiver.recv().await {
//!         match event {
//!             HaiEvent::BenchmarkJob(job) => println!("Job: {}", job.job_id),
//!             HaiEvent::Heartbeat(hb) => println!("Heartbeat: {}", hb.timestamp),
//!             HaiEvent::Unknown { event, data } => println!("Unknown: {} - {}", event, data),
//!         }
//!     }
//!
//!     client.disconnect().await;
//!     Ok(())
//! }
//! ```

use crate::AgentWrapper;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur when interacting with HAI services.
#[derive(Debug)]
pub enum HaiError {
    /// Failed to connect to the HAI server.
    ConnectionFailed(String),
    /// Agent registration failed.
    RegistrationFailed(String),
    /// Authentication is required but not provided.
    AuthRequired,
    /// Invalid response from server.
    InvalidResponse(String),
    /// SSE stream disconnected.
    StreamDisconnected(String),
    /// Already connected to SSE stream.
    AlreadyConnected,
    /// Not connected to SSE stream.
    NotConnected,
    /// Validation error (e.g. verify link would exceed max URL length).
    ValidationError(String),
}

impl fmt::Display for HaiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HaiError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            HaiError::RegistrationFailed(msg) => write!(f, "Registration failed: {}", msg),
            HaiError::AuthRequired => write!(f, "Authentication required: provide an API key"),
            HaiError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
            HaiError::StreamDisconnected(msg) => write!(f, "SSE stream disconnected: {}", msg),
            HaiError::AlreadyConnected => write!(f, "Already connected to SSE stream"),
            HaiError::NotConnected => write!(f, "Not connected to SSE stream"),
            HaiError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

// =============================================================================
// Verify link (HAI / public verification URLs)
// =============================================================================

/// Maximum length for a full verify URL. Re-exported from jacs::simple for bindings.
pub const MAX_VERIFY_URL_LEN: usize = jacs::simple::MAX_VERIFY_URL_LEN;

/// Maximum document size (UTF-8 bytes) for a verify link. Re-exported from jacs::simple.
pub const MAX_VERIFY_DOCUMENT_BYTES: usize = jacs::simple::MAX_VERIFY_DOCUMENT_BYTES;

/// Build a verification URL for a signed JACS document (e.g. https://hai.ai/jacs/verify?s=...).
///
/// Encodes `document` as URL-safe base64. Returns an error if the URL would exceed [`MAX_VERIFY_URL_LEN`].
pub fn generate_verify_link(document: &str, base_url: &str) -> Result<String, HaiError> {
    jacs::simple::generate_verify_link(document, base_url)
        .map_err(|e| HaiError::ValidationError(e.to_string()))
}

impl std::error::Error for HaiError {}

// =============================================================================
// SSE Event Types
// =============================================================================

/// A benchmark job received from the HAI event stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkJob {
    /// Unique identifier for the job.
    pub job_id: String,
    /// The benchmark scenario to run.
    pub scenario: String,
    /// Optional additional parameters for the job.
    #[serde(default)]
    pub params: serde_json::Value,
}

/// A heartbeat event from the HAI event stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// ISO 8601 timestamp of the heartbeat.
    pub timestamp: String,
}

/// Events received from the HAI SSE stream.
#[derive(Debug, Clone)]
pub enum HaiEvent {
    /// A new benchmark job to execute.
    BenchmarkJob(BenchmarkJob),
    /// Heartbeat to confirm connection is alive.
    Heartbeat(Heartbeat),
    /// Unknown event type (forward compatibility).
    Unknown {
        /// The event type name.
        event: String,
        /// The raw JSON data.
        data: String,
    },
}

// =============================================================================
// Response Types
// =============================================================================

/// Signature information returned from HAI registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaiSignature {
    /// Key identifier used for signing.
    pub key_id: String,
    /// Algorithm used (e.g., "Ed25519", "ECDSA-P256").
    pub algorithm: String,
    /// Base64-encoded signature.
    pub signature: String,
    /// ISO 8601 timestamp of when the signature was created.
    pub signed_at: String,
}

/// Result of a successful agent registration with HAI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResult {
    /// The agent's unique identifier.
    pub agent_id: String,
    /// The JACS document ID assigned by HAI.
    pub jacs_id: String,
    /// Whether DNS verification was successful.
    pub dns_verified: bool,
    /// Signatures from HAI attesting to the registration.
    pub signatures: Vec<HaiSignature>,
}

/// Result of checking agent registration status with HAI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResult {
    /// Whether the agent is registered with HAI.ai.
    pub registered: bool,
    /// The agent's JACS ID (if registered).
    #[serde(default)]
    pub agent_id: String,
    /// HAI.ai registration ID (if registered).
    #[serde(default)]
    pub registration_id: String,
    /// When the agent was registered (if registered), as ISO 8601 timestamp.
    #[serde(default)]
    pub registered_at: String,
    /// List of HAI signature IDs (if registered).
    #[serde(default)]
    pub hai_signatures: Vec<String>,
}

/// Result of a benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Unique identifier for the benchmark run.
    pub run_id: String,
    /// The benchmark suite that was run.
    pub suite: String,
    /// Overall score (0.0 to 1.0).
    pub score: f64,
    /// Individual test results within the suite.
    #[serde(default)]
    pub results: Vec<BenchmarkTestResult>,
    /// ISO 8601 timestamp of when the benchmark completed.
    pub completed_at: String,
}

/// Individual test result within a benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkTestResult {
    /// Test name.
    pub name: String,
    /// Whether the test passed.
    pub passed: bool,
    /// Test score (0.0 to 1.0).
    pub score: f64,
    /// Optional message (e.g., error details).
    #[serde(default)]
    pub message: String,
}

// =============================================================================
// Internal Request/Response Types
// =============================================================================

#[derive(Serialize)]
struct RegisterRequest {
    agent_json: String,
}

#[derive(Serialize)]
struct BenchmarkRequest {
    agent_id: String,
    suite: String,
}

#[derive(Deserialize)]
struct HealthResponse {
    status: String,
}

// =============================================================================
// HAI Client
// =============================================================================

/// Handle to control an active SSE connection.
///
/// Drop this handle or call `abort()` to stop the SSE stream.
#[derive(Clone)]
pub struct SseHandle {
    shutdown_tx: mpsc::Sender<()>,
}

impl SseHandle {
    /// Signal the SSE stream to disconnect.
    pub async fn abort(&self) {
        let _ = self.shutdown_tx.send(()).await;
    }
}

/// SSE connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected to SSE stream.
    Disconnected,
    /// Attempting to connect.
    Connecting,
    /// Connected and receiving events.
    Connected,
    /// Reconnecting after a disconnect.
    Reconnecting,
}

/// Client for interacting with HAI.ai services.
///
/// Use the builder pattern to configure the client:
/// ```rust,ignore
/// let client = HaiClient::new("https://api.hai.ai")
///     .with_api_key("your-key");
/// ```
pub struct HaiClient {
    endpoint: String,
    api_key: Option<String>,
    client: reqwest::Client,
    /// Current SSE connection state.
    connection_state: Arc<RwLock<ConnectionState>>,
    /// Handle to shutdown the SSE stream.
    sse_handle: Arc<RwLock<Option<SseHandle>>>,
    /// Maximum reconnection attempts (0 = infinite).
    max_reconnect_attempts: u32,
    /// Base delay between reconnection attempts.
    reconnect_delay: Duration,
}

impl HaiClient {
    /// Create a new HAI client targeting the specified endpoint.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Base URL of the HAI API (e.g., "https://api.hai.ai")
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            api_key: None,
            client: reqwest::Client::new(),
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            sse_handle: Arc::new(RwLock::new(None)),
            max_reconnect_attempts: 0, // Infinite by default
            reconnect_delay: Duration::from_secs(1),
        }
    }

    /// Set the API key for authentication.
    ///
    /// This is required for most operations.
    pub fn with_api_key(mut self, api_key: &str) -> Self {
        self.api_key = Some(api_key.to_string());
        self
    }

    /// Set the maximum number of reconnection attempts.
    ///
    /// Set to 0 for infinite retries (default).
    pub fn with_max_reconnect_attempts(mut self, attempts: u32) -> Self {
        self.max_reconnect_attempts = attempts;
        self
    }

    /// Set the base delay between reconnection attempts.
    ///
    /// Default is 1 second. Uses exponential backoff up to 30 seconds.
    pub fn with_reconnect_delay(mut self, delay: Duration) -> Self {
        self.reconnect_delay = delay;
        self
    }

    /// Get the endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Get the current SSE connection state.
    pub async fn connection_state(&self) -> ConnectionState {
        *self.connection_state.read().await
    }

    /// Test connectivity to the HAI server.
    ///
    /// Returns `Ok(true)` if the server is reachable and healthy.
    ///
    /// # Errors
    ///
    /// Returns `HaiError::ConnectionFailed` if the server cannot be reached
    /// or returns an unhealthy status.
    pub async fn testconnection(&self) -> Result<bool, HaiError> {
        let url = format!("{}/health", self.endpoint);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| HaiError::ConnectionFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(HaiError::ConnectionFailed(format!(
                "Server returned status: {}",
                response.status()
            )));
        }

        // Try to parse health response, but accept any 2xx as success
        match response.json::<HealthResponse>().await {
            Ok(health) => Ok(health.status == "ok" || health.status == "healthy"),
            Err(_) => Ok(true), // 2xx without JSON body is still success
        }
    }

    /// Register a JACS agent with HAI.
    ///
    /// The agent must be loaded and have valid keys before registration.
    ///
    /// # Arguments
    ///
    /// * `agent` - A loaded `AgentWrapper` with valid cryptographic keys
    ///
    /// # Errors
    ///
    /// - `HaiError::AuthRequired` - No API key was provided
    /// - `HaiError::RegistrationFailed` - The agent could not be registered
    /// - `HaiError::InvalidResponse` - The server returned an unexpected response
    pub async fn register(&self, agent: &AgentWrapper) -> Result<RegistrationResult, HaiError> {
        let api_key = self.api_key.as_ref().ok_or(HaiError::AuthRequired)?;

        // Get the agent JSON from the wrapper
        let agent_json = agent
            .get_agent_json()
            .map_err(|e| HaiError::RegistrationFailed(e.to_string()))?;

        let url = format!("{}/api/v1/agents/register", self.endpoint);

        let request = RegisterRequest { agent_json };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| HaiError::ConnectionFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "No response body".to_string());
            return Err(HaiError::RegistrationFailed(format!(
                "Status {}: {}",
                status, body
            )));
        }

        response
            .json::<RegistrationResult>()
            .await
            .map_err(|e| HaiError::InvalidResponse(e.to_string()))
    }

    /// Check registration status of an agent with HAI.
    ///
    /// Queries the HAI API to determine if the agent is registered
    /// and retrieves registration details if so.
    ///
    /// # Arguments
    ///
    /// * `agent` - A loaded `AgentWrapper` to check status for
    ///
    /// # Returns
    ///
    /// `StatusResult` with registration details. If the agent is not registered,
    /// `registered` will be `false`.
    ///
    /// # Errors
    ///
    /// - `HaiError::AuthRequired` - No API key was provided
    /// - `HaiError::ConnectionFailed` - Could not connect to HAI server
    /// - `HaiError::InvalidResponse` - The server returned an unexpected response
    pub async fn status(&self, agent: &AgentWrapper) -> Result<StatusResult, HaiError> {
        let api_key = self.api_key.as_ref().ok_or(HaiError::AuthRequired)?;

        // Get the agent JSON and extract the ID
        let agent_json = agent
            .get_agent_json()
            .map_err(|e| HaiError::InvalidResponse(format!("Failed to get agent JSON: {}", e)))?;

        let agent_value: serde_json::Value = serde_json::from_str(&agent_json)
            .map_err(|e| HaiError::InvalidResponse(format!("Failed to parse agent JSON: {}", e)))?;

        let agent_id = agent_value
            .get("jacsId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                HaiError::InvalidResponse("Agent JSON missing jacsId field".to_string())
            })?
            .to_string();

        let url = format!("{}/api/v1/agents/{}/status", self.endpoint, agent_id);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(|e| HaiError::ConnectionFailed(e.to_string()))?;

        // Handle 404 as "not registered"
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(StatusResult {
                registered: false,
                agent_id,
                registration_id: String::new(),
                registered_at: String::new(),
                hai_signatures: Vec::new(),
            });
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "No response body".to_string());
            return Err(HaiError::InvalidResponse(format!(
                "Status {}: {}",
                status, body
            )));
        }

        response
            .json::<StatusResult>()
            .await
            .map(|mut result| {
                // Ensure registered is true for successful responses
                result.registered = true;
                if result.agent_id.is_empty() {
                    result.agent_id = agent_id;
                }
                result
            })
            .map_err(|e| HaiError::InvalidResponse(e.to_string()))
    }

    /// Run a benchmark suite for an agent.
    ///
    /// Submits the agent to run a specific benchmark suite and waits for results.
    ///
    /// # Arguments
    ///
    /// * `agent` - A loaded `AgentWrapper` to benchmark
    /// * `suite` - The benchmark suite name (e.g., "latency", "accuracy", "safety")
    ///
    /// # Returns
    ///
    /// `BenchmarkResult` with the benchmark run details and scores.
    ///
    /// # Errors
    ///
    /// - `HaiError::AuthRequired` - No API key was provided
    /// - `HaiError::ConnectionFailed` - Could not connect to HAI server
    /// - `HaiError::InvalidResponse` - The server returned an unexpected response
    pub async fn benchmark(
        &self,
        agent: &AgentWrapper,
        suite: &str,
    ) -> Result<BenchmarkResult, HaiError> {
        let api_key = self.api_key.as_ref().ok_or(HaiError::AuthRequired)?;

        // Get the agent ID from the wrapper
        let agent_json = agent
            .get_agent_json()
            .map_err(|e| HaiError::InvalidResponse(format!("Failed to get agent JSON: {}", e)))?;

        let agent_value: serde_json::Value = serde_json::from_str(&agent_json)
            .map_err(|e| HaiError::InvalidResponse(format!("Failed to parse agent JSON: {}", e)))?;

        let agent_id = agent_value
            .get("jacsId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                HaiError::InvalidResponse("Agent JSON missing jacsId field".to_string())
            })?
            .to_string();

        let url = format!("{}/api/v1/benchmarks/run", self.endpoint);

        let request = BenchmarkRequest {
            agent_id,
            suite: suite.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| HaiError::ConnectionFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "No response body".to_string());
            return Err(HaiError::InvalidResponse(format!(
                "Status {}: {}",
                status, body
            )));
        }

        response
            .json::<BenchmarkResult>()
            .await
            .map_err(|e| HaiError::InvalidResponse(e.to_string()))
    }

    // =========================================================================
    // SSE Connection Methods
    // =========================================================================

    /// Connect to the HAI SSE event stream.
    ///
    /// Returns a channel receiver that yields `HaiEvent`s as they arrive.
    /// The connection will automatically attempt to reconnect on disconnection.
    ///
    /// # Errors
    ///
    /// - `HaiError::AuthRequired` - No API key was provided
    /// - `HaiError::AlreadyConnected` - Already connected to SSE stream
    /// - `HaiError::ConnectionFailed` - Initial connection failed
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut receiver = client.connect().await?;
    /// while let Some(event) = receiver.recv().await {
    ///     println!("Received: {:?}", event);
    /// }
    /// ```
    pub async fn connect(&self) -> Result<mpsc::Receiver<HaiEvent>, HaiError> {
        self.connect_to_url(&format!("{}/api/v1/agents/events", self.endpoint))
            .await
    }

    /// Connect to a custom SSE endpoint URL.
    ///
    /// This is useful for testing or connecting to alternative event streams.
    pub async fn connect_to_url(&self, url: &str) -> Result<mpsc::Receiver<HaiEvent>, HaiError> {
        let api_key = self.api_key.as_ref().ok_or(HaiError::AuthRequired)?;

        // Check if already connected
        {
            let state = self.connection_state.read().await;
            if *state != ConnectionState::Disconnected {
                return Err(HaiError::AlreadyConnected);
            }
        }

        // Update state to connecting
        {
            let mut state = self.connection_state.write().await;
            *state = ConnectionState::Connecting;
        }

        // Create channels
        let (event_tx, event_rx) = mpsc::channel::<HaiEvent>(100);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        // Store the handle
        {
            let mut handle = self.sse_handle.write().await;
            *handle = Some(SseHandle {
                shutdown_tx: shutdown_tx.clone(),
            });
        }

        // Clone values for the spawned task
        let client = self.client.clone();
        let url = url.to_string();
        let api_key = api_key.clone();
        let connection_state = self.connection_state.clone();
        let max_attempts = self.max_reconnect_attempts;
        let base_delay = self.reconnect_delay;

        // Spawn the SSE reader task
        tokio::spawn(async move {
            let mut reconnect_attempts = 0u32;

            'reconnect: loop {
                // Attempt connection
                let response = client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Accept", "text/event-stream")
                    .header("Cache-Control", "no-cache")
                    .send()
                    .await;

                let response = match response {
                    Ok(r) if r.status().is_success() => {
                        // Reset reconnect attempts on successful connection
                        reconnect_attempts = 0;
                        {
                            let mut state = connection_state.write().await;
                            *state = ConnectionState::Connected;
                        }
                        r
                    }
                    Ok(r) => {
                        // Non-success status
                        let status = r.status();
                        eprintln!("SSE connection failed with status: {}", status);

                        if should_reconnect(max_attempts, reconnect_attempts) {
                            reconnect_attempts += 1;
                            let delay = calculate_backoff(base_delay, reconnect_attempts);
                            {
                                let mut state = connection_state.write().await;
                                *state = ConnectionState::Reconnecting;
                            }

                            tokio::select! {
                                _ = tokio::time::sleep(delay) => continue 'reconnect,
                                _ = shutdown_rx.recv() => break 'reconnect,
                            }
                        } else {
                            break 'reconnect;
                        }
                    }
                    Err(e) => {
                        eprintln!("SSE connection error: {}", e);

                        if should_reconnect(max_attempts, reconnect_attempts) {
                            reconnect_attempts += 1;
                            let delay = calculate_backoff(base_delay, reconnect_attempts);
                            {
                                let mut state = connection_state.write().await;
                                *state = ConnectionState::Reconnecting;
                            }

                            tokio::select! {
                                _ = tokio::time::sleep(delay) => continue 'reconnect,
                                _ = shutdown_rx.recv() => break 'reconnect,
                            }
                        } else {
                            break 'reconnect;
                        }
                    }
                };

                // Process the SSE stream
                let mut stream = response.bytes_stream();
                let mut buffer = String::new();
                let mut current_event = String::new();
                let mut current_data = String::new();

                loop {
                    tokio::select! {
                        chunk = stream.next() => {
                            match chunk {
                                Some(Ok(bytes)) => {
                                    buffer.push_str(&String::from_utf8_lossy(&bytes));

                                    // Process complete lines
                                    while let Some(newline_pos) = buffer.find('\n') {
                                        let line = buffer[..newline_pos].trim_end_matches('\r').to_string();
                                        buffer = buffer[newline_pos + 1..].to_string();

                                        if line.is_empty() {
                                            // Empty line = end of event
                                            if !current_data.is_empty() {
                                                let event = parse_sse_event(&current_event, &current_data);
                                                if event_tx.send(event).await.is_err() {
                                                    // Receiver dropped, exit
                                                    break 'reconnect;
                                                }
                                            }
                                            current_event.clear();
                                            current_data.clear();
                                        } else if let Some(value) = line.strip_prefix("event:") {
                                            current_event = value.trim().to_string();
                                        } else if let Some(value) = line.strip_prefix("data:") {
                                            if !current_data.is_empty() {
                                                current_data.push('\n');
                                            }
                                            current_data.push_str(value.trim());
                                        }
                                        // Ignore id: and retry: fields for simplicity
                                    }
                                }
                                Some(Err(e)) => {
                                    eprintln!("SSE stream error: {}", e);
                                    break; // Break inner loop to attempt reconnect
                                }
                                None => {
                                    // Stream ended
                                    break; // Break inner loop to attempt reconnect
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            break 'reconnect;
                        }
                    }
                }

                // Stream ended, attempt reconnect
                if should_reconnect(max_attempts, reconnect_attempts) {
                    reconnect_attempts += 1;
                    let delay = calculate_backoff(base_delay, reconnect_attempts);
                    {
                        let mut state = connection_state.write().await;
                        *state = ConnectionState::Reconnecting;
                    }

                    tokio::select! {
                        _ = tokio::time::sleep(delay) => continue 'reconnect,
                        _ = shutdown_rx.recv() => break 'reconnect,
                    }
                } else {
                    break 'reconnect;
                }
            }

            // Clean up
            {
                let mut state = connection_state.write().await;
                *state = ConnectionState::Disconnected;
            }
        });

        Ok(event_rx)
    }

    /// Disconnect from the SSE event stream.
    ///
    /// This is a no-op if not connected.
    pub async fn disconnect(&self) {
        let handle = {
            let mut guard = self.sse_handle.write().await;
            guard.take()
        };

        if let Some(h) = handle {
            h.abort().await;
        }

        // Wait for state to become disconnected
        loop {
            let state = *self.connection_state.read().await;
            if state == ConnectionState::Disconnected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Check if currently connected to the SSE stream.
    pub async fn is_connected(&self) -> bool {
        let state = *self.connection_state.read().await;
        matches!(
            state,
            ConnectionState::Connected | ConnectionState::Reconnecting
        )
    }
}

// =============================================================================
// SSE Helper Functions
// =============================================================================

/// Parse an SSE event into a `HaiEvent`.
fn parse_sse_event(event_type: &str, data: &str) -> HaiEvent {
    match event_type {
        "benchmark_job" => match serde_json::from_str::<BenchmarkJob>(data) {
            Ok(job) => HaiEvent::BenchmarkJob(job),
            Err(_) => HaiEvent::Unknown {
                event: event_type.to_string(),
                data: data.to_string(),
            },
        },
        "heartbeat" => match serde_json::from_str::<Heartbeat>(data) {
            Ok(hb) => HaiEvent::Heartbeat(hb),
            Err(_) => HaiEvent::Unknown {
                event: event_type.to_string(),
                data: data.to_string(),
            },
        },
        _ => HaiEvent::Unknown {
            event: if event_type.is_empty() {
                "message".to_string()
            } else {
                event_type.to_string()
            },
            data: data.to_string(),
        },
    }
}

/// Determine if reconnection should be attempted.
fn should_reconnect(max_attempts: u32, current_attempts: u32) -> bool {
    max_attempts == 0 || current_attempts < max_attempts
}

/// Calculate exponential backoff delay.
fn calculate_backoff(base: Duration, attempt: u32) -> Duration {
    let multiplier = 2u64.saturating_pow(attempt.min(5)); // Cap at 2^5 = 32x
    let delay = base.saturating_mul(multiplier as u32);
    delay.min(Duration::from_secs(30)) // Cap at 30 seconds
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_builder() {
        let client = HaiClient::new("https://api.hai.ai").with_api_key("test-key");

        assert_eq!(client.endpoint, "https://api.hai.ai");
        assert_eq!(client.api_key, Some("test-key".to_string()));
    }

    #[test]
    fn test_endpoint_normalization() {
        let client = HaiClient::new("https://api.hai.ai/");
        assert_eq!(client.endpoint, "https://api.hai.ai");
    }

    #[test]
    fn test_error_display() {
        let err = HaiError::ConnectionFailed("timeout".to_string());
        assert_eq!(format!("{}", err), "Connection failed: timeout");

        let err = HaiError::AuthRequired;
        assert_eq!(
            format!("{}", err),
            "Authentication required: provide an API key"
        );
    }

    #[test]
    fn test_registration_result_serialization() {
        let result = RegistrationResult {
            agent_id: "agent-123".to_string(),
            jacs_id: "jacs-456".to_string(),
            dns_verified: true,
            signatures: vec![HaiSignature {
                key_id: "key-1".to_string(),
                algorithm: "Ed25519".to_string(),
                signature: "c2lnbmF0dXJl".to_string(),
                signed_at: "2024-01-15T10:30:00Z".to_string(),
            }],
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: RegistrationResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.agent_id, "agent-123");
        assert_eq!(parsed.signatures.len(), 1);
    }

    #[test]
    fn test_status_result_serialization() {
        let result = StatusResult {
            registered: true,
            agent_id: "agent-123".to_string(),
            registration_id: "reg-456".to_string(),
            registered_at: "2024-01-15T10:30:00Z".to_string(),
            hai_signatures: vec!["sig-1".to_string(), "sig-2".to_string()],
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: StatusResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.registered, true);
        assert_eq!(parsed.agent_id, "agent-123");
        assert_eq!(parsed.registration_id, "reg-456");
        assert_eq!(parsed.hai_signatures.len(), 2);
    }

    #[test]
    fn test_status_result_not_registered() {
        let result = StatusResult {
            registered: false,
            agent_id: "agent-123".to_string(),
            registration_id: String::new(),
            registered_at: String::new(),
            hai_signatures: Vec::new(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: StatusResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.registered, false);
        assert_eq!(parsed.agent_id, "agent-123");
        assert!(parsed.registration_id.is_empty());
    }

    // =========================================================================
    // SSE Tests
    // =========================================================================

    #[test]
    fn test_parse_sse_event_benchmark_job() {
        let data = r#"{"job_id": "job-123", "scenario": "latency-test"}"#;
        let event = parse_sse_event("benchmark_job", data);

        match event {
            HaiEvent::BenchmarkJob(job) => {
                assert_eq!(job.job_id, "job-123");
                assert_eq!(job.scenario, "latency-test");
            }
            _ => panic!("Expected BenchmarkJob event"),
        }
    }

    #[test]
    fn test_parse_sse_event_heartbeat() {
        let data = r#"{"timestamp": "2024-01-15T10:30:00Z"}"#;
        let event = parse_sse_event("heartbeat", data);

        match event {
            HaiEvent::Heartbeat(hb) => {
                assert_eq!(hb.timestamp, "2024-01-15T10:30:00Z");
            }
            _ => panic!("Expected Heartbeat event"),
        }
    }

    #[test]
    fn test_parse_sse_event_unknown() {
        let data = r#"{"custom": "data"}"#;
        let event = parse_sse_event("custom_event", data);

        match event {
            HaiEvent::Unknown { event, data: d } => {
                assert_eq!(event, "custom_event");
                assert_eq!(d, r#"{"custom": "data"}"#);
            }
            _ => panic!("Expected Unknown event"),
        }
    }

    #[test]
    fn test_parse_sse_event_empty_type_defaults_to_message() {
        let data = r#"{"some": "data"}"#;
        let event = parse_sse_event("", data);

        match event {
            HaiEvent::Unknown { event, .. } => {
                assert_eq!(event, "message");
            }
            _ => panic!("Expected Unknown event with 'message' type"),
        }
    }

    #[test]
    fn test_parse_sse_event_invalid_json_becomes_unknown() {
        let data = "not valid json";
        let event = parse_sse_event("benchmark_job", data);

        match event {
            HaiEvent::Unknown { event, data: d } => {
                assert_eq!(event, "benchmark_job");
                assert_eq!(d, "not valid json");
            }
            _ => panic!("Expected Unknown event due to invalid JSON"),
        }
    }

    #[test]
    fn test_should_reconnect_infinite() {
        // max_attempts = 0 means infinite retries
        assert!(should_reconnect(0, 0));
        assert!(should_reconnect(0, 100));
        assert!(should_reconnect(0, u32::MAX - 1));
    }

    #[test]
    fn test_should_reconnect_limited() {
        assert!(should_reconnect(3, 0));
        assert!(should_reconnect(3, 1));
        assert!(should_reconnect(3, 2));
        assert!(!should_reconnect(3, 3));
        assert!(!should_reconnect(3, 4));
    }

    #[test]
    fn test_calculate_backoff() {
        let base = Duration::from_secs(1);

        // First attempt: 1 * 2^1 = 2 seconds
        assert_eq!(calculate_backoff(base, 1), Duration::from_secs(2));

        // Second attempt: 1 * 2^2 = 4 seconds
        assert_eq!(calculate_backoff(base, 2), Duration::from_secs(4));

        // Third attempt: 1 * 2^3 = 8 seconds
        assert_eq!(calculate_backoff(base, 3), Duration::from_secs(8));

        // High attempts should cap at 30 seconds
        assert_eq!(calculate_backoff(base, 10), Duration::from_secs(30));
        assert_eq!(calculate_backoff(base, 100), Duration::from_secs(30));
    }

    #[test]
    fn test_benchmark_job_serialization() {
        let job = BenchmarkJob {
            job_id: "job-123".to_string(),
            scenario: "latency".to_string(),
            params: serde_json::json!({"timeout": 30}),
        };

        let json = serde_json::to_string(&job).unwrap();
        let parsed: BenchmarkJob = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.job_id, "job-123");
        assert_eq!(parsed.scenario, "latency");
        assert_eq!(parsed.params["timeout"], 30);
    }

    #[test]
    fn test_benchmark_result_serialization() {
        let result = BenchmarkResult {
            run_id: "run-123".to_string(),
            suite: "accuracy".to_string(),
            score: 0.95,
            results: vec![
                BenchmarkTestResult {
                    name: "test-1".to_string(),
                    passed: true,
                    score: 1.0,
                    message: String::new(),
                },
                BenchmarkTestResult {
                    name: "test-2".to_string(),
                    passed: false,
                    score: 0.9,
                    message: "Minor deviation".to_string(),
                },
            ],
            completed_at: "2024-01-15T10:30:00Z".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: BenchmarkResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.run_id, "run-123");
        assert_eq!(parsed.suite, "accuracy");
        assert!((parsed.score - 0.95).abs() < f64::EPSILON);
        assert_eq!(parsed.results.len(), 2);
        assert_eq!(parsed.results[0].name, "test-1");
        assert!(parsed.results[0].passed);
        assert!(!parsed.results[1].passed);
        assert_eq!(parsed.results[1].message, "Minor deviation");
    }

    #[test]
    fn test_heartbeat_serialization() {
        let hb = Heartbeat {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
        };

        let json = serde_json::to_string(&hb).unwrap();
        let parsed: Heartbeat = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.timestamp, "2024-01-15T10:30:00Z");
    }

    #[test]
    fn test_sse_error_display() {
        let err = HaiError::StreamDisconnected("timeout".to_string());
        assert_eq!(format!("{}", err), "SSE stream disconnected: timeout");

        let err = HaiError::AlreadyConnected;
        assert_eq!(format!("{}", err), "Already connected to SSE stream");

        let err = HaiError::NotConnected;
        assert_eq!(format!("{}", err), "Not connected to SSE stream");
    }

    #[test]
    fn test_connection_state_default() {
        let client = HaiClient::new("https://api.hai.ai");

        // Can't test async state easily in sync test, but we can verify
        // the client was created with default settings
        assert_eq!(client.max_reconnect_attempts, 0);
        assert_eq!(client.reconnect_delay, Duration::from_secs(1));
    }

    #[test]
    fn test_client_builder_with_sse_options() {
        let client = HaiClient::new("https://api.hai.ai")
            .with_api_key("test-key")
            .with_max_reconnect_attempts(5)
            .with_reconnect_delay(Duration::from_millis(500));

        assert_eq!(client.max_reconnect_attempts, 5);
        assert_eq!(client.reconnect_delay, Duration::from_millis(500));
    }

    #[tokio::test]
    async fn test_connect_requires_api_key() {
        let client = HaiClient::new("https://api.hai.ai");
        // No API key set

        let result = client.connect().await;
        assert!(matches!(result, Err(HaiError::AuthRequired)));
    }

    #[tokio::test]
    async fn test_connection_state_starts_disconnected() {
        let client = HaiClient::new("https://api.hai.ai").with_api_key("test-key");

        let state = client.connection_state().await;
        assert_eq!(state, ConnectionState::Disconnected);
    }

    #[tokio::test]
    async fn test_is_connected_when_disconnected() {
        let client = HaiClient::new("https://api.hai.ai").with_api_key("test-key");

        assert!(!client.is_connected().await);
    }

    #[tokio::test]
    async fn test_disconnect_when_not_connected() {
        let client = HaiClient::new("https://api.hai.ai").with_api_key("test-key");

        // Should be a no-op, not panic
        client.disconnect().await;
        assert_eq!(
            client.connection_state().await,
            ConnectionState::Disconnected
        );
    }
}
