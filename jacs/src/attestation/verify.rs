//! Attestation verification: local (crypto-only) and full (evidence + chain).
//!
//! Two tiers per TRD Section 4.9:
//! - `verify_attestation_local()`: crypto + hash only. Hot-path default. No network.
//! - `verify_attestation_full()`: crypto + evidence digests + freshness + derivation chain.

use crate::agent::boilerplate::BoilerPlate;
use crate::agent::canonicalize_json;
use crate::agent::document::DocumentTraits;
use crate::agent::{Agent, DOCUMENT_AGENT_SIGNATURE_FIELDNAME};
use crate::attestation::digest::compute_digest_set_bytes;
use crate::attestation::types::*;
use crate::crypt::hash::hash_string;
use serde_json::Value;
use std::error::Error;
use tracing::info;

/// Maximum derivation chain depth. Configurable via `JACS_MAX_DERIVATION_DEPTH` env var.
fn max_derivation_depth() -> u32 {
    std::env::var("JACS_MAX_DERIVATION_DEPTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10)
}

/// Parse a simple ISO 8601 duration string into seconds.
/// Supports: PnY, PnM (months), PnD, PTnH, PTnM (minutes), PTnS and combinations.
/// Uses standard approximations: 1 year = 365.25 days, 1 month = 30.44 days.
pub fn parse_iso8601_duration_secs(duration: &str) -> Result<i64, Box<dyn Error>> {
    if !duration.starts_with('P') {
        return Err(format!(
            "Invalid ISO 8601 duration: must start with 'P': '{}'",
            duration
        )
        .into());
    }
    let rest = &duration[1..];
    let mut seconds: i64 = 0;
    let mut in_time = false;
    let mut num_buf = String::new();

    for ch in rest.chars() {
        match ch {
            'T' => {
                in_time = true;
            }
            '0'..='9' | '.' => {
                num_buf.push(ch);
            }
            'Y' if !in_time => {
                let n: f64 = num_buf
                    .parse()
                    .map_err(|_| format!("Invalid number in duration: '{}'", num_buf))?;
                seconds += (n * 365.25 * 86400.0) as i64;
                num_buf.clear();
            }
            'M' if !in_time => {
                // Months in the date section (before 'T')
                let n: f64 = num_buf
                    .parse()
                    .map_err(|_| format!("Invalid number in duration: '{}'", num_buf))?;
                seconds += (n * 30.44 * 86400.0) as i64;
                num_buf.clear();
            }
            'D' if !in_time => {
                let n: f64 = num_buf
                    .parse()
                    .map_err(|_| format!("Invalid number in duration: '{}'", num_buf))?;
                seconds += (n * 86400.0) as i64;
                num_buf.clear();
            }
            'H' if in_time => {
                let n: f64 = num_buf
                    .parse()
                    .map_err(|_| format!("Invalid number in duration: '{}'", num_buf))?;
                seconds += (n * 3600.0) as i64;
                num_buf.clear();
            }
            'M' if in_time => {
                let n: f64 = num_buf
                    .parse()
                    .map_err(|_| format!("Invalid number in duration: '{}'", num_buf))?;
                seconds += (n * 60.0) as i64;
                num_buf.clear();
            }
            'S' if in_time => {
                let n: f64 = num_buf
                    .parse()
                    .map_err(|_| format!("Invalid number in duration: '{}'", num_buf))?;
                seconds += n as i64;
                num_buf.clear();
            }
            _ => {
                return Err(format!(
                    "Unexpected character '{}' in ISO 8601 duration '{}'",
                    ch, duration
                )
                .into());
            }
        }
    }

    if seconds == 0 && !num_buf.is_empty() {
        return Err(format!("Incomplete ISO 8601 duration: '{}'", duration).into());
    }

    Ok(seconds)
}

/// Verify the hash of a document by recomputing it.
fn verify_document_hash(doc_value: &Value) -> Result<bool, Box<dyn Error>> {
    let stored_hash = doc_value
        .get("jacsSha256")
        .and_then(|v| v.as_str())
        .ok_or("Document missing jacsSha256 field")?;

    let mut doc_copy = doc_value.clone();
    doc_copy.as_object_mut().map(|obj| obj.remove("jacsSha256"));
    let canonical = canonicalize_json(&doc_copy)?;
    let computed_hash = hash_string(&canonical);

    Ok(stored_hash == computed_hash)
}

/// Verify the crypto signature of a document. Returns Ok(()) on success, Err on failure.
fn verify_document_crypto(agent: &Agent, doc_value: &Value) -> Result<(), Box<dyn Error>> {
    let public_key = agent.get_public_key()?;
    agent.signature_verification_procedure(
        doc_value,
        None,
        DOCUMENT_AGENT_SIGNATURE_FIELDNAME,
        public_key,
        None,
        None,
        None,
    )
}

/// Extract signer info from the document's signature block.
fn extract_signer_info(doc_value: &Value) -> (String, String) {
    let sig_block = &doc_value["jacsSignature"];
    let signer_id = sig_block["agentID"].as_str().unwrap_or("").to_string();
    let algorithm = sig_block["signingAlgorithm"]
        .as_str()
        .unwrap_or("")
        .to_string();
    (signer_id, algorithm)
}

/// Verify embedded evidence digest.
fn verify_evidence_ref(evidence: &EvidenceRef) -> EvidenceVerificationResult {
    let digest_valid = if let Some(ref data) = evidence.embedded_data {
        let data_bytes = match data {
            Value::String(s) => {
                // Try base64 decode first, fall back to raw string bytes
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s)
                    .unwrap_or_else(|_| s.as_bytes().to_vec())
            }
            other => serde_json::to_string(other)
                .unwrap_or_default()
                .into_bytes(),
        };
        let recomputed = compute_digest_set_bytes(&data_bytes);
        recomputed.sha256 == evidence.digests.sha256
    } else {
        // Cannot verify referenced (non-embedded) evidence without fetching
        false
    };

    EvidenceVerificationResult {
        kind: format!("{:?}", evidence.kind).to_lowercase(),
        digest_valid,
        freshness_valid: true, // Updated by full verification
        detail: if digest_valid {
            "Evidence digest verified".into()
        } else if evidence.embedded_data.is_none() {
            "Cannot verify referenced evidence without fetching".into()
        } else {
            "Evidence digest mismatch".into()
        },
    }
}

/// Check evidence freshness against a max age duration.
fn check_evidence_freshness(collected_at: &str, max_age_iso: &str) -> Result<bool, Box<dyn Error>> {
    let max_age_secs = parse_iso8601_duration_secs(max_age_iso)?;
    let collected = chrono::DateTime::parse_from_rfc3339(collected_at)
        .map_err(|e| format!("Invalid collectedAt timestamp '{}': {}", collected_at, e))?;
    let now = chrono::Utc::now();
    let age = now.signed_duration_since(collected);
    Ok(age.num_seconds() <= max_age_secs)
}

impl Agent {
    /// Verify attestation: crypto + hash only. No network, no derivation walk.
    /// This is the hot-path default for local verification.
    #[tracing::instrument(
        name = "jacs.attestation.verify_local",
        skip(self),
        fields(document_key)
    )]
    pub fn verify_attestation_local_impl(
        &self,
        document_key: &str,
    ) -> Result<AttestationVerificationResult, Box<dyn Error>> {
        let document = self.get_document(document_key)?;
        let doc_value = document.getvalue();

        // Verify hash
        let hash_valid = verify_document_hash(doc_value)?;

        // Verify signature
        let sig_result = verify_document_crypto(self, doc_value);
        let signature_valid = sig_result.is_ok();

        let (signer_id, algorithm) = extract_signer_info(doc_value);

        let mut errors = Vec::new();
        if !hash_valid {
            errors.push(
                "Document hash verification failed: jacsSha256 does not match recomputed hash"
                    .into(),
            );
        }
        if !signature_valid {
            if let Err(e) = sig_result {
                errors.push(format!("Signature verification failed: {}", e));
            }
        }

        let valid = hash_valid && signature_valid;

        info!(
            target: "jacs::attestation::verify",
            event = "attestation_verify_local",
            tier = "local",
            document_key = %document_key,
            valid = valid,
            hash_valid = hash_valid,
            signature_valid = signature_valid,
        );

        Ok(AttestationVerificationResult {
            valid,
            crypto: CryptoVerificationResult {
                signature_valid,
                hash_valid,
                signer_id,
                algorithm,
            },
            evidence: vec![], // Local tier does not check evidence
            chain: None,      // Local tier does not walk derivation chain
            errors,
        })
    }

    /// Verify attestation: crypto + evidence + derivation chain.
    /// Full verification includes evidence digest checks, freshness, and chain traversal.
    #[tracing::instrument(
        name = "jacs.attestation.verify_full",
        skip(self),
        fields(document_key)
    )]
    pub fn verify_attestation_full_impl(
        &self,
        document_key: &str,
    ) -> Result<AttestationVerificationResult, Box<dyn Error>> {
        let document = self.get_document(document_key)?;
        let doc_value = document.getvalue().clone();

        // Step 1: Local crypto verification
        let hash_valid = verify_document_hash(&doc_value)?;
        let sig_result = verify_document_crypto(self, &doc_value);
        let signature_valid = sig_result.is_ok();
        let (signer_id, algorithm) = extract_signer_info(&doc_value);

        let mut errors = Vec::new();
        if !hash_valid {
            errors.push("Document hash verification failed".into());
        }
        if !signature_valid {
            if let Err(e) = &sig_result {
                errors.push(format!("Signature verification failed: {}", e));
            }
        }

        // Step 2: Evidence verification
        let mut evidence_results = Vec::new();
        let attestation = &doc_value["attestation"];

        // Parse evidence refs from the document
        if let Some(evidence_arr) = attestation["evidence"].as_array() {
            // Get max evidence age from policy context
            let max_age = attestation["policyContext"]["maxEvidenceAge"]
                .as_str()
                .map(|s| s.to_string());

            for evidence_val in evidence_arr {
                if let Ok(evidence_ref) =
                    serde_json::from_value::<EvidenceRef>(evidence_val.clone())
                {
                    // Dispatch to registered adapter if one matches the evidence kind,
                    // falling back to the generic verify_evidence_ref().
                    #[cfg(feature = "attestation")]
                    let kind_str = evidence_ref.kind.as_str();
                    #[cfg(feature = "attestation")]
                    let mut ev_result = if let Some(adapter) =
                        self.adapters.iter().find(|a| a.kind() == kind_str)
                    {
                        match adapter.verify_evidence(&evidence_ref) {
                            Ok(r) => r,
                            Err(e) => {
                                errors.push(format!("Adapter '{}' error: {}", kind_str, e));
                                verify_evidence_ref(&evidence_ref)
                            }
                        }
                    } else {
                        verify_evidence_ref(&evidence_ref)
                    };
                    #[cfg(not(feature = "attestation"))]
                    let mut ev_result = verify_evidence_ref(&evidence_ref);

                    // Check freshness if policy specifies max age
                    if let Some(ref max_age_str) = max_age {
                        match check_evidence_freshness(&evidence_ref.collected_at, max_age_str) {
                            Ok(fresh) => {
                                ev_result.freshness_valid = fresh;
                                if !fresh {
                                    errors.push(format!(
                                        "Evidence '{}' is stale: collected at {} exceeds maxEvidenceAge {}",
                                        ev_result.kind, evidence_ref.collected_at, max_age_str
                                    ));
                                }
                            }
                            Err(e) => {
                                ev_result.freshness_valid = false;
                                errors.push(format!("Failed to check evidence freshness: {}", e));
                            }
                        }
                    }

                    if !ev_result.digest_valid {
                        errors.push(format!(
                            "Evidence '{}' digest verification failed",
                            ev_result.kind
                        ));
                    }

                    // Warn if confidential evidence is embedded
                    if evidence_ref.sensitivity == EvidenceSensitivity::Confidential
                        && evidence_ref.embedded
                    {
                        errors.push(format!(
                            "Evidence '{}' is marked confidential but has embedded data — \
                             confidential evidence should not be embedded",
                            ev_result.kind
                        ));
                    }

                    evidence_results.push(ev_result);
                }
            }
        }

        // Step 3: Derivation chain verification
        let chain = if !attestation["derivation"].is_null() {
            let max_depth = max_derivation_depth();
            match self.walk_derivation_chain(&doc_value, 0, max_depth) {
                Ok(chain_result) => {
                    if !chain_result.valid {
                        errors.push("Derivation chain verification failed".into());
                    }
                    Some(chain_result)
                }
                Err(e) => {
                    errors.push(format!("Derivation chain error: {}", e));
                    Some(ChainVerificationResult {
                        valid: false,
                        depth: 0,
                        max_depth,
                        links: vec![],
                    })
                }
            }
        } else {
            None
        };

        let all_evidence_valid = evidence_results
            .iter()
            .all(|e| e.digest_valid && e.freshness_valid);
        let chain_valid = chain.as_ref().map(|c| c.valid).unwrap_or(true);
        let valid = hash_valid && signature_valid && all_evidence_valid && chain_valid;

        info!(
            target: "jacs::attestation::verify",
            event = "attestation_verify_full",
            tier = "full",
            document_key = %document_key,
            valid = valid,
            evidence_count = evidence_results.len(),
            has_chain = chain.is_some(),
        );

        Ok(AttestationVerificationResult {
            valid,
            crypto: CryptoVerificationResult {
                signature_valid,
                hash_valid,
                signer_id,
                algorithm,
            },
            evidence: evidence_results,
            chain,
            errors,
        })
    }

    /// Walk the derivation chain recursively, verifying each input.
    fn walk_derivation_chain(
        &self,
        doc_value: &Value,
        current_depth: u32,
        max_depth: u32,
    ) -> Result<ChainVerificationResult, Box<dyn Error>> {
        if current_depth >= max_depth {
            return Err(format!(
                "Derivation chain depth {} exceeds maximum {} (set JACS_MAX_DERIVATION_DEPTH to increase)",
                current_depth, max_depth
            )
            .into());
        }

        let derivation = &doc_value["attestation"]["derivation"];
        if derivation.is_null() {
            return Ok(ChainVerificationResult {
                valid: true,
                depth: current_depth,
                max_depth,
                links: vec![],
            });
        }

        let mut links = Vec::new();
        let mut all_valid = true;

        // Check each input in the derivation
        if let Some(inputs) = derivation["inputs"].as_array() {
            for input in inputs {
                if let Some(input_id) = input["id"].as_str() {
                    // Try to retrieve the input document
                    match self.get_document(input_id) {
                        Ok(input_doc) => {
                            let input_value = input_doc.getvalue();
                            let hash_ok = verify_document_hash(input_value).unwrap_or(false);
                            let sig_ok = verify_document_crypto(self, input_value).is_ok();
                            let link_valid = hash_ok && sig_ok;

                            if !link_valid {
                                all_valid = false;
                            }

                            links.push(ChainLink {
                                document_id: input_id.to_string(),
                                valid: link_valid,
                                detail: if link_valid {
                                    "Input document verified".into()
                                } else {
                                    format!(
                                        "Input document verification failed (hash: {}, sig: {})",
                                        hash_ok, sig_ok
                                    )
                                },
                            });

                            // Recursively verify if the input has its own derivation
                            if !input_value["attestation"]["derivation"].is_null() {
                                let input_owned = input_value.clone();
                                match self.walk_derivation_chain(
                                    &input_owned,
                                    current_depth + 1,
                                    max_depth,
                                ) {
                                    Ok(sub_chain) => {
                                        if !sub_chain.valid {
                                            all_valid = false;
                                        }
                                        links.extend(sub_chain.links);
                                    }
                                    Err(e) => {
                                        all_valid = false;
                                        links.push(ChainLink {
                                            document_id: input_id.to_string(),
                                            valid: false,
                                            detail: format!("Sub-chain error: {}", e),
                                        });
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            // Input document not found in storage
                            let detail = if let Some(expected) = input["digests"]["sha256"].as_str()
                            {
                                format!(
                                    "Input document not found in storage (expected sha256: {})",
                                    expected
                                )
                            } else {
                                "Input document not found in storage".into()
                            };
                            links.push(ChainLink {
                                document_id: input_id.to_string(),
                                valid: false,
                                detail,
                            });
                            all_valid = false;
                        }
                    }
                }
            }
        }

        Ok(ChainVerificationResult {
            valid: all_valid,
            depth: current_depth + 1,
            max_depth,
            links,
        })
    }
}

/// Wire the AttestationTraits methods to the impl methods on Agent.
/// This allows the trait to dispatch to the real implementations.
impl super::AttestationTraits for Agent {
    fn create_attestation(
        &mut self,
        subject: &AttestationSubject,
        claims: &[Claim],
        evidence: &[EvidenceRef],
        derivation: Option<&Derivation>,
        policy_context: Option<&PolicyContext>,
    ) -> Result<crate::agent::document::JACSDocument, Box<dyn Error>> {
        // Delegate to create.rs implementation
        crate::attestation::create::create_attestation_impl(
            self,
            subject,
            claims,
            evidence,
            derivation,
            policy_context,
        )
    }

    fn verify_attestation_local(
        &self,
        document_key: &str,
    ) -> Result<AttestationVerificationResult, Box<dyn Error>> {
        self.verify_attestation_local_impl(document_key)
    }

    fn verify_attestation_full(
        &self,
        document_key: &str,
    ) -> Result<AttestationVerificationResult, Box<dyn Error>> {
        self.verify_attestation_full_impl(document_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AttestationTraits;
    use crate::attestation::digest::compute_digest_set_string;
    use crate::attestation::types::*;
    use serde_json::json;
    use std::collections::HashMap;

    /// Helper: create a loaded ephemeral Agent for testing.
    fn test_agent() -> Agent {
        let algo = "ring-Ed25519";
        let mut agent = Agent::ephemeral(algo).expect("create ephemeral agent");
        let agent_json = crate::create_minimal_blank_agent("ai".to_string(), None, None, None)
            .expect("create agent template");
        agent
            .create_agent_and_load(&agent_json, true, Some(algo))
            .expect("load ephemeral agent");
        agent
    }

    fn test_subject() -> AttestationSubject {
        AttestationSubject {
            subject_type: SubjectType::Agent,
            id: "test-agent-123".into(),
            digests: DigestSet {
                sha256: compute_digest_set_string("test-content").sha256,
                sha512: None,
                additional: HashMap::new(),
            },
        }
    }

    fn test_claim() -> Claim {
        Claim {
            name: "test-claim".into(),
            value: json!("ok"),
            confidence: None,
            assurance_level: None,
            issuer: None,
            issued_at: None,
        }
    }

    fn test_evidence() -> EvidenceRef {
        let data = b"evidence-data";
        EvidenceRef {
            kind: EvidenceKind::A2a,
            digests: compute_digest_set_bytes(data),
            uri: None,
            embedded: true,
            embedded_data: Some(json!(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                data
            ))),
            collected_at: crate::time_utils::now_rfc3339(),
            resolved_at: None,
            sensitivity: EvidenceSensitivity::Public,
            verifier: VerifierInfo {
                name: "test-verifier".into(),
                version: "1.0".into(),
            },
        }
    }

    #[test]
    fn verify_local_valid_attestation() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];
        let doc = agent
            .create_attestation(&subject, &claims, &[], None, None)
            .unwrap();
        let key = format!("{}:{}", doc.id, doc.version);

        let result = agent.verify_attestation_local_impl(&key).unwrap();
        assert!(
            result.valid,
            "Valid attestation should verify: {:?}",
            result.errors
        );
        assert!(result.crypto.signature_valid);
        assert!(result.crypto.hash_valid);
    }

    #[test]
    fn verify_local_tampered_hash() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];
        let doc = agent
            .create_attestation(&subject, &claims, &[], None, None)
            .unwrap();
        let key = format!("{}:{}", doc.id, doc.version);

        // Tamper with the stored document's hash by re-storing with wrong hash
        let mut tampered = doc.value.clone();
        tampered["jacsSha256"] = json!("tampered_hash_value");
        agent.store_jacs_document(&tampered).unwrap();

        let result = agent.verify_attestation_local_impl(&key).unwrap();
        assert!(!result.valid, "Tampered hash should fail verification");
        assert!(!result.crypto.hash_valid);
    }

    #[test]
    fn verify_local_tampered_signature() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];
        let doc = agent
            .create_attestation(&subject, &claims, &[], None, None)
            .unwrap();
        let key = format!("{}:{}", doc.id, doc.version);

        // Tamper with the signature by re-storing with wrong sig
        let mut tampered = doc.value.clone();
        if let Some(sig) = tampered.get_mut("jacsSignature") {
            sig["signature"] = json!("tampered_signature_value");
        }
        agent.store_jacs_document(&tampered).unwrap();

        let result = agent.verify_attestation_local_impl(&key).unwrap();
        assert!(!result.valid, "Tampered signature should fail verification");
        assert!(!result.crypto.signature_valid);
    }

    #[test]
    fn verify_local_returns_signer_info() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];
        let doc = agent
            .create_attestation(&subject, &claims, &[], None, None)
            .unwrap();
        let key = format!("{}:{}", doc.id, doc.version);

        let result = agent.verify_attestation_local_impl(&key).unwrap();
        assert!(
            !result.crypto.signer_id.is_empty(),
            "signer_id should be non-empty"
        );
        assert!(
            !result.crypto.algorithm.is_empty(),
            "algorithm should be non-empty"
        );
    }

    #[test]
    fn verify_local_skips_evidence() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];
        let evidence = vec![test_evidence()];
        let doc = agent
            .create_attestation(&subject, &claims, &evidence, None, None)
            .unwrap();
        let key = format!("{}:{}", doc.id, doc.version);

        let result = agent.verify_attestation_local_impl(&key).unwrap();
        assert!(result.valid);
        assert!(
            result.evidence.is_empty(),
            "Local verify should skip evidence checks"
        );
    }

    #[test]
    fn verify_local_skips_chain() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];
        let derivation = Derivation {
            inputs: vec![DerivationInput {
                digests: compute_digest_set_string("input"),
                id: None,
            }],
            transform: TransformRef {
                name: "test".into(),
                hash: "hash".into(),
                reproducible: true,
                environment: None,
            },
            output_digests: compute_digest_set_string("output"),
        };
        let doc = agent
            .create_attestation(&subject, &claims, &[], Some(&derivation), None)
            .unwrap();
        let key = format!("{}:{}", doc.id, doc.version);

        let result = agent.verify_attestation_local_impl(&key).unwrap();
        assert!(result.valid);
        assert!(
            result.chain.is_none(),
            "Local verify should skip derivation chain"
        );
    }

    #[test]
    fn verify_full_checks_evidence_digests() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];
        let evidence = vec![test_evidence()];
        let doc = agent
            .create_attestation(&subject, &claims, &evidence, None, None)
            .unwrap();
        let key = format!("{}:{}", doc.id, doc.version);

        let result = agent.verify_attestation_full_impl(&key).unwrap();
        assert_eq!(result.evidence.len(), 1);
        assert!(
            result.evidence[0].digest_valid,
            "Embedded evidence digest should verify"
        );
    }

    #[test]
    fn verify_full_returns_all_evidence_results() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];
        let evidence = vec![test_evidence(), test_evidence()];
        let doc = agent
            .create_attestation(&subject, &claims, &evidence, None, None)
            .unwrap();
        let key = format!("{}:{}", doc.id, doc.version);

        let result = agent.verify_attestation_full_impl(&key).unwrap();
        assert_eq!(
            result.evidence.len(),
            2,
            "Should return results for all evidence refs"
        );
    }

    #[test]
    fn parse_iso8601_pt5m() {
        assert_eq!(parse_iso8601_duration_secs("PT5M").unwrap(), 300);
    }

    #[test]
    fn parse_iso8601_pt1h() {
        assert_eq!(parse_iso8601_duration_secs("PT1H").unwrap(), 3600);
    }

    #[test]
    fn parse_iso8601_pt1h30m() {
        assert_eq!(parse_iso8601_duration_secs("PT1H30M").unwrap(), 5400);
    }

    #[test]
    fn parse_iso8601_p1d() {
        assert_eq!(parse_iso8601_duration_secs("P1D").unwrap(), 86400);
    }

    #[test]
    fn parse_iso8601_invalid() {
        assert!(parse_iso8601_duration_secs("5M").is_err());
    }

    #[test]
    fn parse_iso8601_p6m_months() {
        // 6 months: 6 * 30.44 days * 86400 sec/day
        assert_eq!(
            parse_iso8601_duration_secs("P6M").unwrap(),
            (6.0_f64 * 30.44 * 86400.0) as i64
        );
    }

    #[test]
    fn parse_iso8601_p1y() {
        // 1 year: 365.25 days * 86400 sec/day = 31,557,600
        assert_eq!(
            parse_iso8601_duration_secs("P1Y").unwrap(),
            (365.25_f64 * 86400.0) as i64
        );
    }

    #[test]
    fn parse_iso8601_p1y6m() {
        // 1 year + 6 months
        let expected = (365.25_f64 * 86400.0) as i64 + (6.0_f64 * 30.44 * 86400.0) as i64;
        assert_eq!(parse_iso8601_duration_secs("P1Y6M").unwrap(), expected);
    }

    #[test]
    fn parse_iso8601_p1y6m3dt12h() {
        // 1 year + 6 months + 3 days + 12 hours
        let expected = (365.25_f64 * 86400.0) as i64
            + (6.0_f64 * 30.44 * 86400.0) as i64
            + (3.0_f64 * 86400.0) as i64
            + (12.0_f64 * 3600.0) as i64;
        assert_eq!(
            parse_iso8601_duration_secs("P1Y6M3DT12H").unwrap(),
            expected
        );
    }
}
