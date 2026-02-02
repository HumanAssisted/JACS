//! Rate limiting utilities for network operations.
//!
//! This module provides a token bucket rate limiter that can be used to control
//! the rate of outgoing HTTP requests and other network operations.
//!
//! # Example
//!
//! ```
//! use jacs::rate_limit::RateLimiter;
//! use std::time::Duration;
//!
//! // Create a rate limiter: 10 requests per second, burst of 5
//! let limiter = RateLimiter::new(10.0, 5);
//!
//! // Before making a request, acquire a permit
//! limiter.acquire(); // Blocks if rate limit exceeded
//!
//! // Or check without blocking
//! if limiter.try_acquire() {
//!     // Make request
//! }
//! ```
//!
//! # Thread Safety
//!
//! The [`RateLimiter`] is thread-safe and can be shared across threads using `Arc`.
//!
//! # Network Operations Using Rate Limiting
//!
//! The following network operations in JACS can benefit from rate limiting:
//! - Remote schema fetching (`schema/utils.rs::get_remote_schema`)
//! - Agent lookup CLI commands (`bin/cli.rs`)
//! - HTTP storage backend operations (`storage/mod.rs`)
//! - OpenTelemetry OTLP exports (`observability/`)

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A thread-safe token bucket rate limiter.
///
/// The token bucket algorithm works by maintaining a bucket of tokens that refills
/// at a constant rate. Each operation consumes one token. If no tokens are available,
/// the operation must wait.
///
/// # Parameters
///
/// - `rate`: Tokens added per second (requests per second)
/// - `burst`: Maximum tokens the bucket can hold (burst capacity)
#[derive(Debug)]
pub struct RateLimiter {
    state: Mutex<RateLimiterState>,
    rate: f64,
    burst: u32,
}

#[derive(Debug)]
struct RateLimiterState {
    tokens: f64,
    last_update: Instant,
}

impl RateLimiter {
    /// Creates a new rate limiter.
    ///
    /// # Arguments
    ///
    /// * `rate` - Number of tokens (requests) allowed per second
    /// * `burst` - Maximum number of tokens that can accumulate (burst capacity)
    ///
    /// # Panics
    ///
    /// Panics if `rate` is not positive or `burst` is zero.
    ///
    /// # Example
    ///
    /// ```
    /// use jacs::rate_limit::RateLimiter;
    ///
    /// // 5 requests per second, burst capacity of 10
    /// let limiter = RateLimiter::new(5.0, 10);
    /// ```
    pub fn new(rate: f64, burst: u32) -> Self {
        assert!(rate > 0.0, "rate must be positive");
        assert!(burst > 0, "burst must be at least 1");

        Self {
            state: Mutex::new(RateLimiterState {
                tokens: burst as f64,
                last_update: Instant::now(),
            }),
            rate,
            burst,
        }
    }

    /// Creates a rate limiter with common defaults for HTTP operations.
    ///
    /// Uses 10 requests per second with a burst of 5.
    pub fn default_http() -> Self {
        Self::new(10.0, 5)
    }

    /// Creates a rate limiter suitable for schema fetching.
    ///
    /// Uses 2 requests per second with a burst of 3.
    /// Schemas are typically cached, so lower rate is acceptable.
    pub fn for_schema_fetch() -> Self {
        Self::new(2.0, 3)
    }

    /// Creates a rate limiter suitable for telemetry/observability exports.
    ///
    /// Uses 1 request per second with a burst of 2.
    pub fn for_telemetry() -> Self {
        Self::new(1.0, 2)
    }

    /// Attempts to acquire a token without blocking.
    ///
    /// Returns `true` if a token was acquired, `false` if rate limit exceeded.
    ///
    /// # Example
    ///
    /// ```
    /// use jacs::rate_limit::RateLimiter;
    ///
    /// let limiter = RateLimiter::new(10.0, 5);
    /// if limiter.try_acquire() {
    ///     // Proceed with operation
    /// } else {
    ///     // Rate limit exceeded, retry later
    /// }
    /// ```
    pub fn try_acquire(&self) -> bool {
        let mut state = self.state.lock().expect("rate limiter lock poisoned");
        self.refill_tokens(&mut state);

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Acquires a token, blocking if necessary until one is available.
    ///
    /// This method will sleep if no tokens are available, then retry.
    ///
    /// # Warning
    ///
    /// This method blocks the calling thread using `std::thread::sleep`.
    /// In async contexts (Tokio, async-std), use `tokio::task::spawn_blocking`
    /// or similar to avoid blocking the runtime.
    ///
    /// // TODO: Add async variant `acquire_async()` that uses tokio::time::sleep
    /// // instead of std::thread::sleep for better async runtime compatibility.
    ///
    /// # Example
    ///
    /// ```
    /// use jacs::rate_limit::RateLimiter;
    ///
    /// let limiter = RateLimiter::new(10.0, 5);
    /// limiter.acquire(); // May block
    /// // Proceed with operation
    /// ```
    pub fn acquire(&self) {
        loop {
            {
                let mut state = self.state.lock().expect("rate limiter lock poisoned");
                self.refill_tokens(&mut state);

                if state.tokens >= 1.0 {
                    state.tokens -= 1.0;
                    return;
                }
            }

            // Calculate sleep time until next token available
            let sleep_duration = Duration::from_secs_f64(1.0 / self.rate);
            std::thread::sleep(sleep_duration);
        }
    }

    /// Acquires a token with a timeout.
    ///
    /// Returns `true` if a token was acquired within the timeout,
    /// `false` if the timeout expired.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait for a token
    ///
    /// # Example
    ///
    /// ```
    /// use jacs::rate_limit::RateLimiter;
    /// use std::time::Duration;
    ///
    /// let limiter = RateLimiter::new(1.0, 1);
    /// if limiter.acquire_timeout(Duration::from_secs(5)) {
    ///     // Got token within 5 seconds
    /// } else {
    ///     // Timed out
    /// }
    /// ```
    pub fn acquire_timeout(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;

        loop {
            {
                let mut state = self.state.lock().expect("rate limiter lock poisoned");
                self.refill_tokens(&mut state);

                if state.tokens >= 1.0 {
                    state.tokens -= 1.0;
                    return true;
                }
            }

            if Instant::now() >= deadline {
                return false;
            }

            // Sleep for a short interval before retrying
            let sleep_duration = Duration::from_secs_f64(1.0 / self.rate).min(Duration::from_millis(100));
            let remaining = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(sleep_duration.min(remaining));
        }
    }

    /// Returns the current number of available tokens (approximate).
    ///
    /// This is primarily useful for debugging and monitoring.
    pub fn available_tokens(&self) -> f64 {
        let mut state = self.state.lock().expect("rate limiter lock poisoned");
        self.refill_tokens(&mut state);
        state.tokens
    }

    /// Returns the configured rate (tokens per second).
    pub fn rate(&self) -> f64 {
        self.rate
    }

    /// Returns the configured burst capacity.
    pub fn burst(&self) -> u32 {
        self.burst
    }

    /// Refills tokens based on elapsed time since last update.
    fn refill_tokens(&self, state: &mut RateLimiterState) {
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_update).as_secs_f64();
        let tokens_to_add = elapsed * self.rate;

        state.tokens = (state.tokens + tokens_to_add).min(self.burst as f64);
        state.last_update = now;
    }
}

impl Default for RateLimiter {
    /// Creates a rate limiter with default settings (10 req/s, burst of 5).
    fn default() -> Self {
        Self::default_http()
    }
}

/// Configuration for rate limiting behavior.
///
/// This can be used to configure rate limiting from application configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests allowed per second
    pub requests_per_second: f64,
    /// Burst capacity (max tokens)
    pub burst_size: u32,
    /// Whether rate limiting is enabled
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 10.0,
            burst_size: 5,
            enabled: true,
        }
    }
}

impl RateLimitConfig {
    /// Creates a rate limiter from this configuration.
    ///
    /// Returns `None` if rate limiting is disabled.
    pub fn build(&self) -> Option<RateLimiter> {
        if self.enabled {
            Some(RateLimiter::new(self.requests_per_second, self.burst_size))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_creation() {
        let limiter = RateLimiter::new(10.0, 5);
        assert_eq!(limiter.rate(), 10.0);
        assert_eq!(limiter.burst(), 5);
    }

    #[test]
    fn test_initial_burst_available() {
        let limiter = RateLimiter::new(10.0, 5);
        // Should be able to acquire burst amount immediately
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
        // Next one should fail (no time to refill)
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn test_default_constructors() {
        let http = RateLimiter::default_http();
        assert_eq!(http.rate(), 10.0);
        assert_eq!(http.burst(), 5);

        let schema = RateLimiter::for_schema_fetch();
        assert_eq!(schema.rate(), 2.0);
        assert_eq!(schema.burst(), 3);

        let telemetry = RateLimiter::for_telemetry();
        assert_eq!(telemetry.rate(), 1.0);
        assert_eq!(telemetry.burst(), 2);
    }

    #[test]
    fn test_refill_over_time() {
        let limiter = RateLimiter::new(100.0, 5); // 100/s for fast test

        // Exhaust burst
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
        assert!(!limiter.try_acquire());

        // Wait for refill (10ms = 1 token at 100/s)
        std::thread::sleep(Duration::from_millis(15));
        assert!(limiter.try_acquire());
    }

    #[test]
    fn test_acquire_blocking() {
        let limiter = RateLimiter::new(100.0, 1);

        // Exhaust the single token
        assert!(limiter.try_acquire());

        // Blocking acquire should work after short wait
        let start = Instant::now();
        limiter.acquire();
        let elapsed = start.elapsed();

        // Should have waited approximately 10ms (1/100s)
        assert!(elapsed.as_millis() >= 5);
    }

    #[test]
    fn test_acquire_timeout_success() {
        let limiter = RateLimiter::new(100.0, 1);
        assert!(limiter.try_acquire());

        // Should succeed within timeout
        assert!(limiter.acquire_timeout(Duration::from_millis(50)));
    }

    #[test]
    fn test_acquire_timeout_failure() {
        let limiter = RateLimiter::new(1.0, 1); // Very slow rate
        assert!(limiter.try_acquire());

        // Should fail with short timeout
        assert!(!limiter.acquire_timeout(Duration::from_millis(10)));
    }

    #[test]
    fn test_config_build() {
        let config = RateLimitConfig {
            requests_per_second: 5.0,
            burst_size: 3,
            enabled: true,
        };
        let limiter = config.build();
        assert!(limiter.is_some());
        let limiter = limiter.unwrap();
        assert_eq!(limiter.rate(), 5.0);
        assert_eq!(limiter.burst(), 3);
    }

    #[test]
    fn test_config_disabled() {
        let config = RateLimitConfig {
            requests_per_second: 5.0,
            burst_size: 3,
            enabled: false,
        };
        assert!(config.build().is_none());
    }

    #[test]
    #[should_panic(expected = "rate must be positive")]
    fn test_invalid_rate() {
        RateLimiter::new(0.0, 5);
    }

    #[test]
    #[should_panic(expected = "burst must be at least 1")]
    fn test_invalid_burst() {
        RateLimiter::new(10.0, 0);
    }
}
