//! `CoreAgentHandle` — the wasm-bindgen wrapper around `jacs_core::CoreAgent`.
//!
//! Exports the constructors and instance methods promised by PRD §4.3 with
//! the exact JS-facing camelCase names (`createEphemeral`,
//! `importEncryptedAgent`, `signMessageJson`, `verifyJson`,
//! `verifyWithKeyJson`, `exportAgent`, `getPublicKeyBase64`, `algorithm`,
//! `isUnlocked`, `clearSecrets`).
//!
//! Every fallible operation returns a `JsError` carrying a JSON payload
//! shaped `{ code, message, details? }` (the wire shape jacs-core uses for
//! `CoreError`). Browser callers can `try { … } catch (e) { e.code }` and
//! pattern-match on the stable code discriminator.

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use jacs_core::agreements;
use jacs_core::{
    AgentMaterial, CoreAgent, CoreError, SigningAlgorithm, UnlockSecret, VerificationOutcome,
};
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasm_bindgen::prelude::*;

use crate::init_jacs_wasm;

// ---------------------------------------------------------------------------
// Per-handle metrics + debug logging (Issue 006 / Task 031 — PRD §10.2)
// ---------------------------------------------------------------------------

/// Snapshot of per-handle counters + last-call durations. Wire shape
/// returned by `CoreAgentHandle.metrics()` (PRD §10.2). All durations
/// are in milliseconds; zero before the first call.
#[derive(Debug, Default, Clone, Serialize)]
struct HandleMetrics {
    #[serde(rename = "signCount")]
    sign_count: u64,
    #[serde(rename = "verifyCount")]
    verify_count: u64,
    #[serde(rename = "lastSignDurationMs")]
    last_sign_duration_ms: f64,
    #[serde(rename = "lastVerifyDurationMs")]
    last_verify_duration_ms: f64,
}

/// Read `globalThis.JACS_WASM_DEBUG`. Returns `true` only if the
/// property is set to JS-truthy `true`. Off by default (PRD §10.2 —
/// "Off by default").
fn debug_enabled() -> bool {
    // Reading from globalThis is the canonical way to expose a runtime
    // flag in the browser without env vars. The check is cheap (single
    // Reflect::get); we still gate behind the flag to keep the hot path
    // free of `console.debug` allocations when the flag is off.
    #[cfg(target_arch = "wasm32")]
    {
        let global = js_sys::global();
        match js_sys::Reflect::get(&global, &JsValue::from_str("JACS_WASM_DEBUG")) {
            Ok(v) => v.as_bool().unwrap_or(false),
            Err(_) => false,
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Native tests use the `JACS_WASM_DEBUG` env var as a
        // stand-in so the metric / log path is unit-testable.
        std::env::var("JACS_WASM_DEBUG")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }
}

/// Emit a `console.debug` line — no-op when `debug_enabled()` is false.
fn debug_log(line: &str) {
    if !debug_enabled() {
        return;
    }
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::console::debug_1(&JsValue::from_str(line));
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        eprintln!("[jacs-wasm debug] {}", line);
    }
}

/// Cheap monotonic timer source. Uses `performance.now()` in the
/// browser, falls back to `std::time::Instant` natively.
fn now_ms() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        // Try `performance.now()` first; if there is no `window`
        // (e.g. running inside a Worker without performance), fall
        // back to `Date.now()`.
        if let Some(perf) = web_sys::window().and_then(|w| w.performance()) {
            return perf.now();
        }
        js_sys::Date::now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Native: emulate `performance.now()` with a monotonic Instant
        // measured against a process-local epoch so subtraction yields
        // ms with sub-ms resolution.
        use std::sync::OnceLock;
        use std::time::Instant;
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        let epoch = EPOCH.get_or_init(Instant::now);
        epoch.elapsed().as_secs_f64() * 1000.0
    }
}

// ---------------------------------------------------------------------------
// Error mapping — one helper so every method goes through the same path.
// ---------------------------------------------------------------------------

/// Convert a `CoreError` into a `JsError` whose message is the JSON form
/// `{ code, message, details? }`. JS callers do
/// `JSON.parse(err.message).code` to dispatch.
fn map_core_err(err: CoreError) -> JsError {
    let payload = serde_json::to_string(&err)
        .unwrap_or_else(|_| format!("{{\"code\":\"{}\",\"message\":\"{}\"}}", err.code(), err));
    JsError::new(&payload)
}

/// Convert a JS algorithm string into the canonical enum, returning a
/// `JsError` with code `UnsupportedAlgorithm` on miss.
fn parse_algorithm(raw: &str) -> Result<SigningAlgorithm, JsError> {
    SigningAlgorithm::from_wire_str(raw).ok_or_else(|| {
        map_core_err(CoreError::UnsupportedAlgorithm(format!(
            "unknown signing algorithm '{}' (expected one of: ed25519, pq2025)",
            raw
        )))
    })
}

// ---------------------------------------------------------------------------
// CoreAgentHandle
// ---------------------------------------------------------------------------

/// JS handle for a `jacs_core::CoreAgent`. Cloneable via `Arc` so wasm-
/// bindgen can hand multiple references to JS without giving up
/// `&mut self` semantics on the inner agent.
///
/// `verifier_override` is `Some` only for handles produced by
/// `create_verifier`. Verifier handles report the override key from
/// `getPublicKeyBase64` and use it to satisfy `verifyJson` (which would
/// otherwise read the inner `CoreAgent`'s ephemeral key). The static
/// `verifyWithKeyJson` is unaffected — it takes the key as an explicit
/// argument.
#[wasm_bindgen]
pub struct CoreAgentHandle {
    inner: Arc<Mutex<CoreAgent>>,
    verifier_override: Option<(Vec<u8>, SigningAlgorithm)>,
    metrics: Arc<Mutex<HandleMetrics>>,
}

#[wasm_bindgen]
impl CoreAgentHandle {
    /// Sign a JSON payload, returning the signed document as a JSON string.
    ///
    /// Increments `signCount` + records `lastSignDurationMs` on the
    /// handle's metrics, and (when `globalThis.JACS_WASM_DEBUG` is
    /// truthy) emits a `console.debug` line bracketing the call.
    #[wasm_bindgen(js_name = signMessageJson)]
    pub fn sign_message_json(&self, data_json: &str) -> Result<String, JsError> {
        debug_log("signMessageJson: start");
        let started_at = now_ms();
        let payload: Value = serde_json::from_str(data_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "invalid input JSON: {}",
                e
            )))
        })?;
        let mut agent = self
            .inner
            .lock()
            .map_err(|_| map_core_err(CoreError::AgreementFailed("agent lock poisoned".into())))?;
        let signed = agent.sign_message(&payload).map_err(map_core_err)?;
        let out = serde_json::to_string(&signed).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "serialize signed doc: {}",
                e
            )))
        });
        // Record metrics regardless of serialize outcome — the sign
        // succeeded, that's what the counter measures. Drop the agent
        // lock first so the metrics lock can't deadlock against it.
        drop(agent);
        let elapsed = now_ms() - started_at;
        if let Ok(mut m) = self.metrics.lock() {
            m.sign_count = m.sign_count.saturating_add(1);
            m.last_sign_duration_ms = elapsed;
        }
        debug_log(&format!("signMessageJson: done in {:.3}ms", elapsed));
        out
    }

    /// Verify a signed JACS document. Returns a JSON string of
    /// `VerificationOutcome` (`{ valid, signer_id, timestamp, data,
    /// errors }`). A cryptographic failure does **not** throw — it
    /// returns `valid: false` with the error in `errors[]`. A
    /// missing-field / algorithm-mismatch failure throws.
    ///
    /// On verifier-override handles (those built via `createVerifier`)
    /// this consults the override key instead of the inner agent's
    /// (cleared, ephemeral) key.
    #[wasm_bindgen(js_name = verifyJson)]
    pub fn verify_json(&self, signed_json: &str) -> Result<String, JsError> {
        debug_log("verifyJson: start");
        let started_at = now_ms();
        let signed: Value = serde_json::from_str(signed_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "invalid signed JSON: {}",
                e
            )))
        })?;
        let outcome = match &self.verifier_override {
            Some((pk, algo)) => {
                CoreAgent::verify_with_key(&signed, pk, *algo).map_err(map_core_err)?
            }
            None => {
                let agent = self.inner.lock().map_err(|_| {
                    map_core_err(CoreError::AgreementFailed("agent lock poisoned".into()))
                })?;
                agent.verify(&signed).map_err(map_core_err)?
            }
        };
        let out = outcome_to_json(&outcome);
        let elapsed = now_ms() - started_at;
        if let Ok(mut m) = self.metrics.lock() {
            m.verify_count = m.verify_count.saturating_add(1);
            m.last_verify_duration_ms = elapsed;
        }
        debug_log(&format!("verifyJson: done in {:.3}ms", elapsed));
        out
    }

    /// Static verify path — does not require the handle to be unlocked.
    /// `public_key_base64` is the standard base64 encoding (no URL
    /// alphabet, padding included) of the raw public-key bytes.
    #[wasm_bindgen(js_name = verifyWithKeyJson)]
    pub fn verify_with_key_json(
        &self,
        signed_json: &str,
        public_key_base64: &str,
        algorithm: &str,
    ) -> Result<String, JsError> {
        debug_log("verifyWithKeyJson: start");
        let started_at = now_ms();
        let signed: Value = serde_json::from_str(signed_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "invalid signed JSON: {}",
                e
            )))
        })?;
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(public_key_base64)
            .map_err(|e| {
                map_core_err(CoreError::MalformedKey(format!(
                    "invalid base64 public key: {}",
                    e
                )))
            })?;
        let algo = parse_algorithm(algorithm)?;
        let outcome =
            CoreAgent::verify_with_key(&signed, &public_key, algo).map_err(map_core_err)?;
        let out = outcome_to_json(&outcome);
        let elapsed = now_ms() - started_at;
        if let Ok(mut m) = self.metrics.lock() {
            m.verify_count = m.verify_count.saturating_add(1);
            m.last_verify_duration_ms = elapsed;
        }
        debug_log(&format!("verifyWithKeyJson: done in {:.3}ms", elapsed));
        out
    }

    /// Return the agent JSON as a string. Always non-empty.
    #[wasm_bindgen(js_name = exportAgent)]
    pub fn export_agent(&self) -> Result<String, JsError> {
        let agent = self
            .inner
            .lock()
            .map_err(|_| map_core_err(CoreError::AgreementFailed("agent lock poisoned".into())))?;
        serde_json::to_string(&agent.export_agent()).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "serialize agent: {}",
                e
            )))
        })
    }

    /// Standard base64 encoding of the raw public-key bytes. For verifier
    /// handles (built via `createVerifier`) returns the override key the
    /// caller passed in, not the inner ephemeral agent's key.
    #[wasm_bindgen(js_name = getPublicKeyBase64)]
    pub fn get_public_key_base64(&self) -> Result<String, JsError> {
        if let Some((pk, _)) = &self.verifier_override {
            return Ok(base64::engine::general_purpose::STANDARD.encode(pk));
        }
        let agent = self
            .inner
            .lock()
            .map_err(|_| map_core_err(CoreError::AgreementFailed("agent lock poisoned".into())))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(agent.public_key()))
    }

    /// The signing algorithm tag, as one of `"ed25519"` / `"pq2025"`. For
    /// verifier handles returns the override algorithm the caller passed
    /// to `createVerifier`.
    #[wasm_bindgen]
    pub fn algorithm(&self) -> Result<String, JsError> {
        if let Some((_, algo)) = &self.verifier_override {
            return Ok(algo.as_str().to_string());
        }
        let agent = self
            .inner
            .lock()
            .map_err(|_| map_core_err(CoreError::AgreementFailed("agent lock poisoned".into())))?;
        Ok(agent.algorithm().as_str().to_string())
    }

    /// Whether the agent currently holds an unlocked private key.
    #[wasm_bindgen(js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> Result<bool, JsError> {
        let agent = self
            .inner
            .lock()
            .map_err(|_| map_core_err(CoreError::AgreementFailed("agent lock poisoned".into())))?;
        Ok(agent.is_unlocked())
    }

    /// Drop the unlocked private key. Idempotent. Subsequent
    /// `signMessageJson` calls throw `JacsWasmError { code: "Locked" }`;
    /// `verifyJson` and `verifyWithKeyJson` continue to work.
    #[wasm_bindgen(js_name = clearSecrets)]
    pub fn clear_secrets(&self) -> Result<(), JsError> {
        debug_log("clearSecrets: zeroing in-memory key");
        let mut agent = self
            .inner
            .lock()
            .map_err(|_| map_core_err(CoreError::AgreementFailed("agent lock poisoned".into())))?;
        agent.clear_secrets();
        Ok(())
    }

    /// In-memory metrics snapshot for this handle. Returns the JSON
    /// form of `{ signCount, verifyCount, lastSignDurationMs,
    /// lastVerifyDurationMs }` (PRD §10.2). Counters are per-handle —
    /// independent handles do not share state.
    #[wasm_bindgen(js_name = metrics)]
    pub fn metrics_json(&self) -> Result<String, JsError> {
        let snapshot = match self.metrics.lock() {
            Ok(m) => m.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        serde_json::to_string(&snapshot).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "serialize metrics: {}",
                e
            )))
        })
    }

    // =====================================================================
    // Agreements (Task 018)
    // =====================================================================

    /// Append this agent's signature to a multi-party `jacsAgreement`
    /// document, returning the updated document as a JSON string.
    ///
    /// `agreement_json` must already contain a `jacsAgreement` skeleton
    /// (call `jacs_core::agreements::create` or the equivalent JS helper
    /// to build one). `role` is recorded on the signature entry for
    /// traceability and is **not** part of the canonical bytes (so it
    /// can be edited after signing without invalidating the signature).
    ///
    /// Returns `JacsWasmError { code: "Locked" }` if `clearSecrets` has
    /// been called.
    #[wasm_bindgen(js_name = signAgreementJson)]
    pub fn sign_agreement_json(&self, agreement_json: &str, role: &str) -> Result<String, JsError> {
        let mut document: Value = serde_json::from_str(agreement_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "invalid agreement JSON: {}",
                e
            )))
        })?;
        let mut agent = self
            .inner
            .lock()
            .map_err(|_| map_core_err(CoreError::AgreementFailed("agent lock poisoned".into())))?;
        agreements::sign(&mut agent, &mut document, role).map_err(map_core_err)?;
        serde_json::to_string(&document).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "serialize agreement: {}",
                e
            )))
        })
    }

    /// Verify every signature on a multi-party `jacsAgreement` document
    /// against the supplied list of signer keys.
    ///
    /// `signers_json` is a JSON array of objects shaped
    /// `{ agentId, publicKeyBase64, algorithm }`. `algorithm` is one of
    /// `"ed25519"` / `"pq2025"`; `publicKeyBase64` is the standard
    /// base64 encoding of the raw public-key bytes. Signers absent from
    /// the list surface as `SignerKeyMissing` in the per-signer outcome
    /// (the call does **not** throw — it returns a structured
    /// `QuorumOutcome` JSON the caller can inspect).
    ///
    /// Does not require the handle to be unlocked.
    #[wasm_bindgen(js_name = verifyAgreementJson)]
    pub fn verify_agreement_json(
        &self,
        agreement_json: &str,
        signers_json: &str,
    ) -> Result<String, JsError> {
        let document: Value = serde_json::from_str(agreement_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "invalid agreement JSON: {}",
                e
            )))
        })?;
        let signer_specs: Vec<SignerSpec> = serde_json::from_str(signers_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "invalid signers JSON (expected `[{{agentId, publicKeyBase64, algorithm}}]`): {}",
                e
            )))
        })?;

        // Decode each spec into `(agent_id, public_key_bytes, algorithm)`
        // so we can borrow the references shape `agreements::verify`
        // wants. We keep the decoded bytes alive in `decoded_keys` so
        // the borrows stay valid for the call.
        let mut decoded: Vec<(String, Vec<u8>, SigningAlgorithm)> =
            Vec::with_capacity(signer_specs.len());
        for spec in signer_specs {
            let algo = parse_algorithm(&spec.algorithm)?;
            let pk = base64::engine::general_purpose::STANDARD
                .decode(spec.public_key_base64.as_bytes())
                .map_err(|e| {
                    map_core_err(CoreError::MalformedKey(format!(
                        "invalid base64 public key for signer '{}': {}",
                        spec.agent_id, e
                    )))
                })?;
            decoded.push((spec.agent_id, pk, algo));
        }
        let signers_ref: Vec<(&str, &[u8], SigningAlgorithm)> = decoded
            .iter()
            .map(|(id, pk, algo)| (id.as_str(), pk.as_slice(), *algo))
            .collect();

        let outcome = agreements::verify(&document, &signers_ref).map_err(map_core_err)?;
        serde_json::to_string(&outcome).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "serialize quorum outcome: {}",
                e
            )))
        })
    }

    /// Create a standalone agreement v2 document from a CreateAgreementV2 JSON object.
    #[wasm_bindgen(js_name = createAgreementV2Json)]
    pub fn create_agreement_v2_json(&self, input_json: &str) -> Result<String, JsError> {
        let input: Value = serde_json::from_str(input_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "invalid agreement v2 input JSON: {}",
                e
            )))
        })?;
        let mut agent = self
            .inner
            .lock()
            .map_err(|_| map_core_err(CoreError::AgreementFailed("agent lock poisoned".into())))?;
        let document = agreements::v2::create(&mut agent, &input).map_err(map_core_err)?;
        serde_json::to_string(&document).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "serialize agreement v2: {}",
                e
            )))
        })
    }

    /// Apply an agreement v2 mutation and return the successor document JSON.
    #[wasm_bindgen(js_name = applyAgreementV2Json)]
    pub fn apply_agreement_v2_json(
        &self,
        agreement_json: &str,
        mutation_json: &str,
    ) -> Result<String, JsError> {
        let document: Value = serde_json::from_str(agreement_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "invalid agreement v2 JSON: {}",
                e
            )))
        })?;
        let mutation: Value = serde_json::from_str(mutation_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "invalid agreement v2 mutation JSON: {}",
                e
            )))
        })?;
        let mut agent = self
            .inner
            .lock()
            .map_err(|_| map_core_err(CoreError::AgreementFailed("agent lock poisoned".into())))?;
        let next = agreements::v2::apply(&mut agent, &document, &mutation).map_err(map_core_err)?;
        serde_json::to_string(&next).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "serialize agreement v2 update: {}",
                e
            )))
        })
    }

    /// Add this agent's signer, witness, or notary signature to agreement v2.
    #[wasm_bindgen(js_name = signAgreementV2Json)]
    pub fn sign_agreement_v2_json(
        &self,
        agreement_json: &str,
        role: &str,
    ) -> Result<String, JsError> {
        let document: Value = serde_json::from_str(agreement_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "invalid agreement v2 JSON: {}",
                e
            )))
        })?;
        let mut agent = self
            .inner
            .lock()
            .map_err(|_| map_core_err(CoreError::AgreementFailed("agent lock poisoned".into())))?;
        let next = agreements::v2::sign(&mut agent, &document, role).map_err(map_core_err)?;
        serde_json::to_string(&next).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "serialize signed agreement v2: {}",
                e
            )))
        })
    }

    /// Verify agreement v2 hash/status/transcript invariants. Crypto key lookup is native-layer.
    #[wasm_bindgen(js_name = verifyAgreementV2Json)]
    pub fn verify_agreement_v2_json(&self, agreement_json: &str) -> Result<String, JsError> {
        let document: Value = serde_json::from_str(agreement_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "invalid agreement v2 JSON: {}",
                e
            )))
        })?;
        let report = agreements::v2::verify(&document).map_err(map_core_err)?;
        serde_json::to_string(&report).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "serialize agreement v2 report: {}",
                e
            )))
        })
    }

    /// Analyze whether two agreement v2 branches are transcript-only mergeable.
    #[wasm_bindgen(js_name = detectAgreementV2BranchConflictJson)]
    pub fn detect_agreement_v2_branch_conflict_json(
        &self,
        base_json: &str,
        left_json: &str,
        right_json: &str,
    ) -> Result<String, JsError> {
        let base: Value = serde_json::from_str(base_json)
            .map_err(|e| map_core_err(CoreError::MalformedDocument(format!("base JSON: {}", e))))?;
        let left: Value = serde_json::from_str(left_json)
            .map_err(|e| map_core_err(CoreError::MalformedDocument(format!("left JSON: {}", e))))?;
        let right: Value = serde_json::from_str(right_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!("right JSON: {}", e)))
        })?;
        let analysis =
            agreements::v2::detect_branch_conflict(&base, &left, &right).map_err(map_core_err)?;
        serde_json::to_string(&analysis).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "serialize agreement v2 branch analysis: {}",
                e
            )))
        })
    }

    /// Auto-merge two transcript-only agreement v2 branches.
    #[wasm_bindgen(js_name = mergeAgreementV2TranscriptBranchesJson)]
    pub fn merge_agreement_v2_transcript_branches_json(
        &self,
        base_json: &str,
        left_json: &str,
        right_json: &str,
    ) -> Result<String, JsError> {
        let base: Value = serde_json::from_str(base_json)
            .map_err(|e| map_core_err(CoreError::MalformedDocument(format!("base JSON: {}", e))))?;
        let left: Value = serde_json::from_str(left_json)
            .map_err(|e| map_core_err(CoreError::MalformedDocument(format!("left JSON: {}", e))))?;
        let right: Value = serde_json::from_str(right_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!("right JSON: {}", e)))
        })?;
        let mut agent = self
            .inner
            .lock()
            .map_err(|_| map_core_err(CoreError::AgreementFailed("agent lock poisoned".into())))?;
        let merged = agreements::v2::merge_transcript_branches(&mut agent, &base, &left, &right)
            .map_err(map_core_err)?;
        serde_json::to_string(&merged).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "serialize merged agreement v2: {}",
                e
            )))
        })
    }

    /// Resolve an agreement v2 branch conflict with an explicit mutation.
    #[wasm_bindgen(js_name = resolveAgreementV2BranchConflictJson)]
    pub fn resolve_agreement_v2_branch_conflict_json(
        &self,
        base_json: &str,
        previous_json: &str,
        side_json: &str,
        mutation_json: &str,
    ) -> Result<String, JsError> {
        let base: Value = serde_json::from_str(base_json)
            .map_err(|e| map_core_err(CoreError::MalformedDocument(format!("base JSON: {}", e))))?;
        let previous: Value = serde_json::from_str(previous_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "previous JSON: {}",
                e
            )))
        })?;
        let side: Value = serde_json::from_str(side_json)
            .map_err(|e| map_core_err(CoreError::MalformedDocument(format!("side JSON: {}", e))))?;
        let mutation: Value = serde_json::from_str(mutation_json).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "mutation JSON: {}",
                e
            )))
        })?;
        let mut agent = self
            .inner
            .lock()
            .map_err(|_| map_core_err(CoreError::AgreementFailed("agent lock poisoned".into())))?;
        let resolved =
            agreements::v2::resolve_branch_conflict(&mut agent, &base, &previous, &side, &mutation)
                .map_err(map_core_err)?;
        serde_json::to_string(&resolved).map_err(|e| {
            map_core_err(CoreError::MalformedDocument(format!(
                "serialize resolved agreement v2: {}",
                e
            )))
        })
    }
}

/// JS-facing shape of one entry in `verifyAgreementJson`'s `signers`
/// array. Field names match the TypeScript surface declared in PRD §4.3
/// (`agentId`, `publicKeyBase64`, `algorithm`).
#[derive(Debug, Deserialize)]
struct SignerSpec {
    #[serde(rename = "agentId")]
    agent_id: String,
    #[serde(rename = "publicKeyBase64")]
    public_key_base64: String,
    algorithm: String,
}

/// Build an empty `jacsAgreement` skeleton on `document_json` and return
/// the updated document JSON. Convenience entry point exposed to JS so
/// browser callers can produce a signable agreement without re-
/// implementing the field-name + array shape `jacs_core::agreements`
/// expects. Not strictly required by PRD §4.3 (the agreement object can
/// be constructed in JS by hand) — present so the TypeScript wrapper in
/// Task 020 has a single import that does the right thing.
#[wasm_bindgen(js_name = createAgreementJson)]
pub fn create_agreement_json(
    document_json: &str,
    agent_ids_json: &str,
    question: Option<String>,
    context: Option<String>,
) -> Result<String, JsError> {
    let document: Value = serde_json::from_str(document_json).map_err(|e| {
        map_core_err(CoreError::MalformedDocument(format!(
            "invalid document JSON: {}",
            e
        )))
    })?;
    let agent_ids: Vec<String> = serde_json::from_str(agent_ids_json).map_err(|e| {
        map_core_err(CoreError::MalformedDocument(format!(
            "invalid agent IDs JSON (expected `[\"id1\",\"id2\"]`): {}",
            e
        )))
    })?;
    let updated = agreements::create(
        &document,
        &agent_ids,
        question.as_deref(),
        context.as_deref(),
    )
    .map_err(map_core_err)?;
    serde_json::to_string(&updated).map_err(|e| {
        map_core_err(CoreError::MalformedDocument(format!(
            "serialize agreement skeleton: {}",
            e
        )))
    })
}

// ---------------------------------------------------------------------------
// Constructors — wasm-bindgen exports as free functions, mapped to the JS
// names in PRD §4.3.
// ---------------------------------------------------------------------------

/// Generate a fresh ephemeral agent for the given algorithm. The JS API
/// returns a `Promise<CoreAgentHandle>` (Rust returns the handle
/// synchronously; wasm-bindgen wraps it as a resolved Promise via the
/// generated `.d.ts`).
#[wasm_bindgen(js_name = createEphemeral)]
pub fn create_ephemeral(algorithm: &str) -> Result<CoreAgentHandle, JsError> {
    init_jacs_wasm();
    let algo = parse_algorithm(algorithm)?;
    let agent = CoreAgent::ephemeral(algo).map_err(map_core_err)?;
    Ok(CoreAgentHandle {
        inner: Arc::new(Mutex::new(agent)),
        verifier_override: None,
        metrics: Arc::new(Mutex::new(HandleMetrics::default())),
    })
}

/// Import an encrypted agent from a JSON-serialized `AgentMaterial` blob +
/// password.
#[wasm_bindgen(js_name = importEncryptedAgent)]
pub fn import_encrypted_agent(
    material_json: &str,
    password: &str,
) -> Result<CoreAgentHandle, JsError> {
    init_jacs_wasm();
    let material: AgentMaterial = serde_json::from_str(material_json).map_err(|e| {
        map_core_err(CoreError::MalformedDocument(format!(
            "AgentMaterial JSON: {}",
            e
        )))
    })?;
    let agent = CoreAgent::from_encrypted_material(material, UnlockSecret::Password(password))
        .map_err(map_core_err)?;
    Ok(CoreAgentHandle {
        inner: Arc::new(Mutex::new(agent)),
        verifier_override: None,
        metrics: Arc::new(Mutex::new(HandleMetrics::default())),
    })
}

/// Import an encrypted agent from four separate file-shaped buffers (used
/// by browser file pickers that hand each file individually).
#[wasm_bindgen(js_name = importEncryptedAgentFiles)]
pub fn import_encrypted_agent_files(
    config_text: &str,
    agent_text: &str,
    public_key_bytes: &[u8],
    encrypted_private_key_bytes: &[u8],
    password: &str,
    algorithm: &str,
) -> Result<CoreAgentHandle, JsError> {
    init_jacs_wasm();
    let config: Value = serde_json::from_str(config_text)
        .map_err(|e| map_core_err(CoreError::MalformedDocument(format!("config text: {}", e))))?;
    let agent_json: Value = serde_json::from_str(agent_text)
        .map_err(|e| map_core_err(CoreError::MalformedDocument(format!("agent text: {}", e))))?;
    let algo = parse_algorithm(algorithm)?;
    let material = AgentMaterial {
        config,
        agent: agent_json,
        public_key: public_key_bytes.to_vec(),
        encrypted_private_key: encrypted_private_key_bytes.to_vec(),
        algorithm: algo,
    };
    let agent = CoreAgent::from_encrypted_material(material, UnlockSecret::Password(password))
        .map_err(map_core_err)?;
    Ok(CoreAgentHandle {
        inner: Arc::new(Mutex::new(agent)),
        verifier_override: None,
        metrics: Arc::new(Mutex::new(HandleMetrics::default())),
    })
}

/// Build a verify-only handle from a raw public key. Sign attempts on the
/// returned handle throw `Locked`; verify methods work.
///
/// Internally constructs a `CoreAgent` via `from_encrypted_material` with
/// a placeholder `UnlockSecret::RawPrivateKey` and then immediately
/// `clear_secrets()`s it. This avoids a separate verify-only constructor
/// on `CoreAgent` while keeping the wire contract clean. The placeholder
/// bytes are the matching algorithm's all-zero scalar; that key is
/// immediately wiped and never used to sign.
#[wasm_bindgen(js_name = createVerifier)]
pub fn create_verifier(
    public_key_base64: &str,
    algorithm: &str,
) -> Result<CoreAgentHandle, JsError> {
    init_jacs_wasm();
    let algo = parse_algorithm(algorithm)?;
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(public_key_base64)
        .map_err(|e| {
            map_core_err(CoreError::MalformedKey(format!(
                "invalid base64 public key: {}",
                e
            )))
        })?;
    // Build a CoreAgent whose signer is then immediately cleared so the
    // handle can only verify, never sign. We do this by routing through
    // ephemeral() + replacing the public key after clear_secrets — but
    // the public-key check inside `from_encrypted_material` won't allow
    // a mismatched key. The cleanest path is: generate an ephemeral,
    // clear secrets, then mutate the public key. Since `CoreAgent` has
    // no public mutator for the key, we use the verify-only static path
    // through `CoreAgent::verify_with_key` and stash the key + algorithm
    // in a verifier-only branch.
    //
    // For V1 we use a simpler approach: construct an ephemeral agent of
    // the requested algorithm (which has a different public key), then
    // `clear_secrets()`. Any signing attempt afterwards correctly returns
    // `Locked`. The verifying path takes the explicit `public_key` arg in
    // every call (`verifyWithKeyJson`), so the handle's stored key is
    // never consulted during verification — the caller passes the right
    // one each time. JS callers should treat the verifier handle as a
    // bag for verification context, not as a key holder.
    //
    // We surface the override key + algorithm via `verifier_override` so
    // `getPublicKeyBase64`, `algorithm`, and `verifyJson` all consult
    // them. The inner CoreAgent's ephemeral key/algo are never visible
    // to JS on a verifier handle.
    let mut agent = CoreAgent::ephemeral(algo).map_err(map_core_err)?;
    agent.clear_secrets();
    Ok(CoreAgentHandle {
        inner: Arc::new(Mutex::new(agent)),
        verifier_override: Some((public_key, algo)),
        metrics: Arc::new(Mutex::new(HandleMetrics::default())),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Serialize a `VerificationOutcome` to JSON for the JS caller.
fn outcome_to_json(outcome: &VerificationOutcome) -> Result<String, JsError> {
    serde_json::to_string(outcome).map_err(|e| {
        map_core_err(CoreError::MalformedDocument(format!(
            "serialize verification outcome: {}",
            e
        )))
    })
}

// Suppress the "unused secrecy::SecretBox" import in the path where
// only the `Password` unlock variant is exercised by JS callers right
// now. Kept here so the raw-key path lands cleanly when a JS-side raw-
// key constructor is added (currently out of V1 surface — `secrecy`
// remains a documented internal dependency).
const _UNUSED_SECRECY_IMPORT: fn() = || {
    let _ = SecretBox::new(Box::new(vec![0u8; 32]));
};
