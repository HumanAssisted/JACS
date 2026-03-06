//! Benchmarks for attestation create, verify, and lift operations.
//!
//! Measures:
//! - attestation_create_minimal: create with 1 claim, no evidence
//! - attestation_create_with_evidence: create with 3 evidence refs
//! - attestation_verify_local: local-tier verification (target: <50ms p95)
//! - attestation_verify_full_no_network: full-tier with embedded evidence only
//! - attestation_lift_to_attestation: lift an existing signed document

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use jacs::attestation::types::{
    AssuranceLevel, AttestationSubject, Claim, DigestSet, EvidenceKind, EvidenceRef,
    EvidenceSensitivity, SubjectType, VerifierInfo,
};
use jacs::simple::SimpleAgent;
use serde_json::json;
use std::collections::HashMap;

fn configure_criterion() -> Criterion {
    Criterion::default()
        .sample_size(50)
        .measurement_time(std::time::Duration::from_secs(10))
        .confidence_level(0.95)
        .noise_threshold(0.05)
}

fn make_subject() -> AttestationSubject {
    AttestationSubject {
        subject_type: SubjectType::Artifact,
        id: "bench-artifact-001".to_string(),
        digests: DigestSet {
            sha256: "abc123def456789012345678901234567890abcdef1234567890abcdef12345678"
                .to_string(),
            sha512: None,
            additional: HashMap::new(),
        },
    }
}

fn make_claims(count: usize) -> Vec<Claim> {
    (0..count)
        .map(|i| Claim {
            name: format!("claim_{}", i),
            value: json!(true),
            confidence: Some(0.95),
            assurance_level: Some(AssuranceLevel::Verified),
            issuer: None,
            issued_at: None,
        })
        .collect()
}

fn make_evidence_refs(count: usize) -> Vec<EvidenceRef> {
    (0..count)
        .map(|i| EvidenceRef {
            kind: EvidenceKind::Custom,
            digests: DigestSet {
                sha256: format!(
                    "evidence{}abc123def456789012345678901234567890abcdef12345678",
                    i
                ),
                sha512: None,
                additional: HashMap::new(),
            },
            uri: Some(format!("https://evidence.example.com/{}", i)),
            embedded: false,
            embedded_data: None,
            collected_at: "2026-03-04T00:00:00Z".to_string(),
            resolved_at: None,
            sensitivity: EvidenceSensitivity::Public,
            verifier: VerifierInfo {
                name: "bench-verifier".to_string(),
                version: "1.0.0".to_string(),
            },
        })
        .collect()
}

/// Benchmark: create attestation with 1 claim, no evidence.
fn bench_attestation_create_minimal(c: &mut Criterion) {
    let (agent, _info) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create ephemeral agent");
    let subject = make_subject();
    let claims = make_claims(1);

    c.bench_function("attestation_create_minimal", |b| {
        b.iter(|| {
            black_box(
                agent
                    .create_attestation(&subject, &claims, &[], None, None)
                    .expect("create_attestation"),
            )
        })
    });
}

/// Benchmark: create attestation with 3 evidence refs.
fn bench_attestation_create_with_evidence(c: &mut Criterion) {
    let (agent, _info) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create ephemeral agent");
    let subject = make_subject();
    let claims = make_claims(1);
    let evidence = make_evidence_refs(3);

    c.bench_function("attestation_create_with_evidence", |b| {
        b.iter(|| {
            black_box(
                agent
                    .create_attestation(&subject, &claims, &evidence, None, None)
                    .expect("create_attestation"),
            )
        })
    });
}

/// Benchmark: verify an existing attestation (local tier).
/// Target: <50ms p95.
fn bench_attestation_verify_local(c: &mut Criterion) {
    let (agent, _info) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create ephemeral agent");
    let subject = make_subject();
    let claims = make_claims(1);
    let signed = agent
        .create_attestation(&subject, &claims, &[], None, None)
        .expect("create_attestation");

    // Extract document key for verification
    let doc: serde_json::Value = serde_json::from_str(&signed.raw).unwrap();
    let doc_key = format!(
        "{}:{}",
        doc["jacsId"].as_str().unwrap(),
        doc["jacsVersion"].as_str().unwrap()
    );

    c.bench_function("attestation_verify_local", |b| {
        b.iter(|| {
            black_box(
                agent
                    .verify_attestation(&doc_key)
                    .expect("verify_attestation"),
            )
        })
    });
}

/// Benchmark: verify an existing attestation (full tier, embedded evidence only -- no network).
fn bench_attestation_verify_full_no_network(c: &mut Criterion) {
    let (agent, _info) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create ephemeral agent");
    let subject = make_subject();
    let claims = make_claims(1);
    // Create with evidence refs (non-embedded, so full verify won't need network
    // but will still exercise the full verification path).
    let evidence = make_evidence_refs(3);
    let signed = agent
        .create_attestation(&subject, &claims, &evidence, None, None)
        .expect("create_attestation");

    let doc: serde_json::Value = serde_json::from_str(&signed.raw).unwrap();
    let doc_key = format!(
        "{}:{}",
        doc["jacsId"].as_str().unwrap(),
        doc["jacsVersion"].as_str().unwrap()
    );

    c.bench_function("attestation_verify_full_no_network", |b| {
        b.iter(|| {
            black_box(
                agent
                    .verify_attestation_full(&doc_key)
                    .expect("verify_attestation_full"),
            )
        })
    });
}

/// Benchmark: lift an existing signed document to an attestation.
fn bench_attestation_lift(c: &mut Criterion) {
    let (agent, _info) =
        SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create ephemeral agent");
    let data = json!({"content": "benchmark document for lifting"});
    let signed = agent.sign_message(&data).expect("sign_message");
    let claims = make_claims(1);

    c.bench_function("attestation_lift_to_attestation", |b| {
        b.iter(|| {
            black_box(
                agent
                    .lift_to_attestation(&signed.raw, &claims)
                    .expect("lift_to_attestation"),
            )
        })
    });
}

criterion_group! {
    name = benches;
    config = configure_criterion();
    targets =
        bench_attestation_create_minimal,
        bench_attestation_create_with_evidence,
        bench_attestation_verify_local,
        bench_attestation_verify_full_no_network,
        bench_attestation_lift
}
criterion_main!(benches);
