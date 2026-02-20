use crate::error::JacsError;
use crate::time_utils;
use moka::sync::Cache;
use std::sync::LazyLock;
use std::time::Duration;

const MIN_REPLAY_TTL_SECONDS: i64 = 1;

// Cache seen (scope, nonce) pairs for the active replay window.
static SEEN_NONCES: LazyLock<Cache<String, ()>> = LazyLock::new(|| {
    let ttl = time_utils::max_iat_skew_seconds().max(MIN_REPLAY_TTL_SECONDS) as u64;
    Cache::builder()
        .time_to_live(Duration::from_secs(ttl))
        .max_capacity(200_000)
        .build()
});

fn replay_window_enabled() -> bool {
    time_utils::max_iat_skew_seconds() > 0
}

/// Rejects duplicate nonces observed within the replay window.
///
/// `scope` should identify the signer context (e.g. `agentID`) so two different
/// agents using the same nonce value do not collide.
pub fn check_and_store_nonce(scope: &str, nonce: &str) -> Result<(), JacsError> {
    if !replay_window_enabled() {
        return Ok(());
    }

    let key = format!("{}:{}", scope.trim(), nonce.trim());
    if SEEN_NONCES.contains_key(&key) {
        return Err(JacsError::SignatureVerificationFailed {
            reason: format!(
                "Replay attack detected: nonce '{}' has already been used in this replay window.",
                nonce
            ),
        });
    }

    SEEN_NONCES.insert(key, ());
    Ok(())
}
