//! Replay-attack protection for HTTP / API payload signatures.
//!
//! This is the **only** place in JACS that enforces signature freshness.
//! Document signatures (`agent::*`, `trust::*`, inline media) have no
//! age check by design: a JACS-signed document is valid for the working
//! life of its signing key. Anything in this module applies exclusively
//! to short-lived payload envelopes used over HTTP / RPC transports.
//!
//! Knob: `JACS_PAYLOAD_MAX_REPLAY_SECONDS` (default 300s / 5 min).
//!
//! Future work: cross-check payload `iat` against the signing key's
//! rotation timeline so payloads produced by a rotated-out key are
//! rejected even if their nonce is still within the replay window.

use crate::error::JacsError;
use crate::observability::convenience::{
    SecurityOutcome, SecurityPolicy, SecuritySource, record_security_outcome,
};
use moka::{Expiry, sync::Cache};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;
use tracing::{debug, warn};

pub const DEFAULT_PAYLOAD_MAX_REPLAY_SECONDS: u64 = 300;
const MIN_REPLAY_TTL_SECONDS: i64 = DEFAULT_PAYLOAD_MAX_REPLAY_SECONDS as i64;

/// Returns the payload replay window used by payload verification.
///
/// `JACS_PAYLOAD_MAX_REPLAY_SECONDS` overrides the default.
pub fn payload_replay_window_seconds() -> u64 {
    std::env::var("JACS_PAYLOAD_MAX_REPLAY_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PAYLOAD_MAX_REPLAY_SECONDS)
}

fn effective_replay_window_seconds() -> i64 {
    i64::try_from(payload_replay_window_seconds()).unwrap_or(i64::MAX)
}

/// Whether a replay backend is isolated to one process or shared atomically
/// across service replicas.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ReplayStoreScope {
    ProcessLocal,
    Shared,
}

/// Atomic nonce-consumption backend.
///
/// Implementations must return `Ok(true)` to exactly one concurrent caller
/// for a new key and `Ok(false)` to every duplicate until `ttl` expires.
/// Backend errors must be returned; JACS fails closed on them.
pub trait ReplayStore: Send + Sync {
    fn consume(&self, key: &str, ttl: Duration) -> Result<bool, JacsError>;
    fn name(&self) -> &'static str;
    fn scope(&self) -> ReplayStoreScope;
}

/// Bounded process-local replay store.
///
/// This is suitable for single-process/local development. Multi-replica
/// services should install a shared atomic implementation and set
/// `JACS_REQUIRE_SHARED_REPLAY_STORE=true`.
pub struct InMemoryReplayStore {
    seen: Cache<String, Duration>,
}

#[derive(Debug)]
struct PerEntryTtl;

impl Expiry<String, Duration> for PerEntryTtl {
    fn expire_after_create(
        &self,
        _key: &String,
        ttl: &Duration,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(*ttl)
    }
}

impl InMemoryReplayStore {
    /// Build a bounded process-local store.
    ///
    /// The legacy `default_ttl` argument is retained for source compatibility;
    /// each [`ReplayStore::consume`] call now supplies the authoritative TTL.
    pub fn new(_default_ttl: Duration, max_capacity: u64) -> Self {
        Self {
            seen: Cache::builder()
                .expire_after(PerEntryTtl)
                .max_capacity(max_capacity)
                .build(),
        }
    }
}

impl Default for InMemoryReplayStore {
    fn default() -> Self {
        let ttl = effective_replay_window_seconds().max(MIN_REPLAY_TTL_SECONDS) as u64;
        Self::new(Duration::from_secs(ttl), 200_000)
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn consume(&self, key: &str, ttl: Duration) -> Result<bool, JacsError> {
        if ttl.is_zero() {
            return Err(JacsError::ValidationError(
                "Replay nonce TTL must be greater than zero".to_string(),
            ));
        }
        // Moka's entry insertion is serialized per key. Exactly one caller
        // receives a fresh entry; concurrent duplicates wait and receive the
        // existing entry.
        Ok(self
            .seen
            .entry(key.to_string())
            .or_insert_with(|| ttl)
            .is_fresh())
    }

    fn name(&self) -> &'static str {
        "moka-process-local"
    }

    fn scope(&self) -> ReplayStoreScope {
        ReplayStoreScope::ProcessLocal
    }
}

static REPLAY_STORE: LazyLock<RwLock<Arc<dyn ReplayStore>>> =
    LazyLock::new(|| RwLock::new(Arc::new(InMemoryReplayStore::default())));

/// Install an application-owned replay backend and return the previous one.
///
/// Services should call this once during startup. Returning the old backend
/// makes scoped test configuration and rollback explicit.
pub fn install_replay_store(
    store: Arc<dyn ReplayStore>,
) -> Result<Arc<dyn ReplayStore>, JacsError> {
    let mut current = REPLAY_STORE.write().map_err(|_| JacsError::Internal {
        message: "Replay store lock poisoned while installing backend".to_string(),
    })?;
    Ok(std::mem::replace(&mut *current, store))
}

fn replay_window_enabled() -> bool {
    effective_replay_window_seconds() > 0
}

fn require_shared_replay_store() -> bool {
    std::env::var("JACS_REQUIRE_SHARED_REPLAY_STORE")
        .ok()
        .is_some_and(|value| value.eq_ignore_ascii_case("true") || value == "1")
}

/// Build the domain-separated key passed to every replay backend.
///
/// This is crate-visible so protocol preparation APIs can hand application-
/// owned stores the exact same key that native verification consumes.
pub(crate) fn replay_key(scope: &str, nonce: &str) -> String {
    let scope = scope.trim();
    let nonce = nonce.trim();
    format!("jacs-replay-v1:{}:{scope}:{nonce}", scope.len())
}

fn record_replay_outcome(backend: &str, outcome: &str) {
    let mut labels = HashMap::new();
    labels.insert("backend".to_string(), backend.to_string());
    labels.insert("outcome".to_string(), outcome.to_string());
    crate::observability::metrics::increment_counter("jacs_replay_checks_total", 1, Some(labels));
}

fn check_and_store_nonce_with_policy_and_ttl(
    store: &dyn ReplayStore,
    scope: &str,
    nonce: &str,
    require_shared: bool,
    ttl: Duration,
) -> Result<(), JacsError> {
    if scope.trim().is_empty() || nonce.trim().is_empty() {
        record_replay_outcome(store.name(), "invalid_input");
        record_security_outcome(
            SecuritySource::Replay,
            SecurityOutcome::ParserRejected,
            SecurityPolicy::Strict,
            None,
            Some(nonce),
        );
        warn!(
            event = "replay_nonce_rejected",
            backend = store.name(),
            reason = "empty_scope_or_nonce",
            "Replay nonce rejected before store access"
        );
        return Err(JacsError::ValidationError(
            "Replay scope and nonce must be non-empty".to_string(),
        ));
    }

    if ttl.is_zero() {
        record_replay_outcome(store.name(), "invalid_ttl");
        return Err(JacsError::ValidationError(
            "Replay nonce TTL must be greater than zero".to_string(),
        ));
    }

    if require_shared && store.scope() != ReplayStoreScope::Shared {
        record_replay_outcome(store.name(), "shared_store_required");
        record_security_outcome(
            SecuritySource::Replay,
            SecurityOutcome::StoreUnavailable,
            SecurityPolicy::Strict,
            None,
            Some(nonce),
        );
        warn!(
            event = "replay_store_unavailable",
            backend = store.name(),
            reason = "shared_store_required",
            "Replay verification failed closed because the configured store is process-local"
        );
        return Err(JacsError::Internal {
            message:
                "A shared replay store is required, but only a process-local backend is installed"
                    .to_string(),
        });
    }

    let fresh = match store.consume(&replay_key(scope, nonce), ttl) {
        Ok(fresh) => fresh,
        Err(error) => {
            record_replay_outcome(store.name(), "store_error");
            record_security_outcome(
                SecuritySource::Replay,
                SecurityOutcome::StoreUnavailable,
                SecurityPolicy::Strict,
                None,
                Some(nonce),
            );
            warn!(
                event = "replay_store_error",
                backend = store.name(),
                error_kind = "replay_store_unavailable",
                "Replay verification failed closed because the store returned an error"
            );
            return Err(error);
        }
    };

    if fresh {
        record_replay_outcome(store.name(), "accepted");
        record_security_outcome(
            SecuritySource::Replay,
            SecurityOutcome::Valid,
            SecurityPolicy::Strict,
            None,
            Some(nonce),
        );
        debug!(
            event = "replay_nonce_accepted",
            backend = store.name(),
            "Replay nonce consumed atomically"
        );
        Ok(())
    } else {
        record_replay_outcome(store.name(), "duplicate");
        record_security_outcome(
            SecuritySource::Replay,
            SecurityOutcome::Duplicate,
            SecurityPolicy::Strict,
            None,
            Some(nonce),
        );
        warn!(
            event = "replay_nonce_rejected",
            backend = store.name(),
            reason = "duplicate",
            "Replay nonce rejected"
        );
        Err(JacsError::SignatureVerificationFailed {
            reason: "Replay attack detected: nonce has already been used in this replay window."
                .to_string(),
        })
    }
}

fn check_and_store_nonce_with_policy(
    store: &dyn ReplayStore,
    scope: &str,
    nonce: &str,
    require_shared: bool,
) -> Result<(), JacsError> {
    check_and_store_nonce_with_policy_and_ttl(
        store,
        scope,
        nonce,
        require_shared,
        Duration::from_secs(payload_replay_window_seconds().max(1)),
    )
}

/// Atomically consume a nonce in an explicitly supplied backend for `ttl`.
///
/// This path is suitable for application-owned shared stores: the backend's
/// atomic `consume` implementation is used directly, and backend errors fail
/// verification closed.
pub fn check_and_store_nonce_with_store(
    store: &dyn ReplayStore,
    scope: &str,
    nonce: &str,
    ttl: Duration,
) -> Result<(), JacsError> {
    check_and_store_nonce_with_policy_and_ttl(store, scope, nonce, false, ttl)
}

/// Atomically consume a nonce in the installed backend for the caller's
/// effective credential lifetime.
pub fn check_and_store_nonce_with_ttl(
    scope: &str,
    nonce: &str,
    ttl: Duration,
) -> Result<(), JacsError> {
    let store = REPLAY_STORE
        .read()
        .map_err(|_| JacsError::Internal {
            message: "Replay store lock poisoned while consuming nonce".to_string(),
        })?
        .clone();
    check_and_store_nonce_with_policy_and_ttl(
        store.as_ref(),
        scope,
        nonce,
        require_shared_replay_store(),
        ttl,
    )
}

/// Rejects duplicate nonces observed within the replay window.
///
/// `scope` should identify the signer context (e.g. `agentID`) so two different
/// agents using the same nonce value do not collide.
pub fn check_and_store_nonce(scope: &str, nonce: &str) -> Result<(), JacsError> {
    if !replay_window_enabled() {
        return Ok(());
    }
    let store = REPLAY_STORE
        .read()
        .map_err(|_| JacsError::Internal {
            message: "Replay store lock poisoned while consuming nonce".to_string(),
        })?
        .clone();
    check_and_store_nonce_with_policy(store.as_ref(), scope, nonce, require_shared_replay_store())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn concurrent_nonce_consumption_accepts_exactly_once() {
        const WORKERS: usize = 64;
        let store = Arc::new(InMemoryReplayStore::new(Duration::from_secs(60), 10_000));
        for trial in 0..20 {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let scope = format!("atomic-replay-test-{}-{trial}", std::process::id());
            let nonce = format!("{unique}");
            let barrier = Arc::new(Barrier::new(WORKERS));
            let mut joins = Vec::with_capacity(WORKERS);

            for _ in 0..WORKERS {
                let barrier = Arc::clone(&barrier);
                let scope = scope.clone();
                let nonce = nonce.clone();
                let store = Arc::clone(&store);
                joins.push(thread::spawn(move || {
                    barrier.wait();
                    check_and_store_nonce_with_policy(store.as_ref(), &scope, &nonce, false).is_ok()
                }));
            }

            let accepted = joins
                .into_iter()
                .map(|join| usize::from(join.join().expect("replay worker must not panic")))
                .sum::<usize>();
            assert_eq!(
                accepted, 1,
                "trial {trial}: one nonce must be consumed exactly once"
            );
        }
    }

    #[derive(Default)]
    struct SharedTestStore {
        seen: Mutex<HashSet<String>>,
    }

    impl ReplayStore for SharedTestStore {
        fn consume(&self, key: &str, _ttl: Duration) -> Result<bool, JacsError> {
            let mut seen = self.seen.lock().map_err(|_| JacsError::Internal {
                message: "test replay store lock poisoned".to_string(),
            })?;
            Ok(seen.insert(key.to_string()))
        }

        fn name(&self) -> &'static str {
            "shared-test"
        }

        fn scope(&self) -> ReplayStoreScope {
            ReplayStoreScope::Shared
        }
    }

    struct FailingStore;

    impl ReplayStore for FailingStore {
        fn consume(&self, _key: &str, _ttl: Duration) -> Result<bool, JacsError> {
            Err(JacsError::Internal {
                message: "shared replay backend unavailable".to_string(),
            })
        }

        fn name(&self) -> &'static str {
            "failing-test"
        }

        fn scope(&self) -> ReplayStoreScope {
            ReplayStoreScope::Shared
        }
    }

    #[test]
    fn shared_backend_satisfies_required_policy_and_rejects_duplicate() {
        let store = SharedTestStore::default();
        check_and_store_nonce_with_policy(&store, "agent-a", "nonce-a", true)
            .expect("first shared consumption succeeds");
        let duplicate = check_and_store_nonce_with_policy(&store, "agent-a", "nonce-a", true)
            .expect_err("duplicate must fail");
        assert!(matches!(
            duplicate,
            JacsError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn required_shared_policy_rejects_process_local_backend() {
        let store = InMemoryReplayStore::new(Duration::from_secs(60), 100);
        let error = check_and_store_nonce_with_policy(&store, "agent", "nonce", true)
            .expect_err("process-local store must fail closed");
        assert!(
            matches!(error, JacsError::Internal { ref message } if message.contains("shared replay store"))
        );
    }

    #[test]
    fn replay_store_error_fails_closed() {
        let error = check_and_store_nonce_with_policy(&FailingStore, "agent", "nonce", true)
            .expect_err("backend failure must reject verification");
        assert!(
            matches!(error, JacsError::Internal { ref message } if message.contains("unavailable"))
        );
    }

    #[test]
    fn empty_scope_or_nonce_is_rejected_before_store_access() {
        let store = SharedTestStore::default();
        assert!(check_and_store_nonce_with_policy(&store, "", "nonce", false).is_err());
        assert!(check_and_store_nonce_with_policy(&store, "agent", " ", false).is_err());
        assert!(store.seen.lock().expect("test store lock").is_empty());
    }

    #[test]
    fn in_memory_store_honors_each_callers_ttl() {
        let store = InMemoryReplayStore::new(Duration::from_secs(60), 100);

        assert!(
            store
                .consume("short-lived", Duration::from_millis(20))
                .expect("first short-lived consume")
        );
        assert!(
            store
                .consume("long-lived", Duration::from_secs(2))
                .expect("first long-lived consume")
        );

        thread::sleep(Duration::from_millis(80));

        assert!(
            store
                .consume("short-lived", Duration::from_millis(20))
                .expect("expired entry should be fresh again"),
            "the per-entry TTL must not be replaced by the constructor TTL"
        );
        assert!(
            !store
                .consume("long-lived", Duration::from_secs(2))
                .expect("long-lived duplicate check"),
            "a longer caller TTL must keep the nonce consumed"
        );
    }

    #[derive(Default)]
    struct TtlRecordingStore {
        ttls: Mutex<Vec<Duration>>,
    }

    impl ReplayStore for TtlRecordingStore {
        fn consume(&self, _key: &str, ttl: Duration) -> Result<bool, JacsError> {
            self.ttls.lock().expect("recording store lock").push(ttl);
            Ok(true)
        }

        fn name(&self) -> &'static str {
            "ttl-recording-test"
        }

        fn scope(&self) -> ReplayStoreScope {
            ReplayStoreScope::Shared
        }
    }

    #[test]
    fn explicit_store_path_forwards_the_effective_credential_ttl() {
        let store = TtlRecordingStore::default();
        check_and_store_nonce_with_store(
            &store,
            "signed-event:agent",
            "document-id",
            Duration::from_secs(937),
        )
        .expect("explicit replay store should accept first use");

        assert_eq!(
            store.ttls.lock().expect("recording store lock").as_slice(),
            &[Duration::from_secs(937)]
        );
    }
}
