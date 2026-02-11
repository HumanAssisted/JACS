//! Benchmarks for multi-party agreement creation, signing, and verification.
//!
//! Measures:
//! - Agreement creation + N-party signing for N in {2, 5, 10, 25}
//! - Concurrent SimpleAgent instantiation and signing

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use jacs::simple::SimpleAgent;
use serde_json::json;
use std::sync::Arc;
use std::thread;

fn configure_criterion() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30))
        .confidence_level(0.95)
}

/// Create N ephemeral agents with Ed25519 keys (fast key gen).
/// Returns (agent, agent_id) pairs.
fn create_agents(n: usize) -> Vec<(SimpleAgent, String)> {
    (0..n)
        .map(|_| {
            let (agent, info) =
                SimpleAgent::ephemeral(Some("ed25519")).expect("Failed to create ephemeral agent");
            (agent, info.agent_id)
        })
        .collect()
}

/// Benchmark: create agreement + N agents sign it.
fn bench_agreement_n_party(c: &mut Criterion) {
    let mut group = c.benchmark_group("agreement_sign");

    for n in [2, 5, 10, 25] {
        group.bench_with_input(BenchmarkId::new("agents", n), &n, |b, &n| {
            let agents = create_agents(n);
            let agent_ids: Vec<String> = agents.iter().map(|(_, id)| id.clone()).collect();
            let doc_data = json!({"proposal": "benchmark test", "version": n});
            let doc_str = doc_data.to_string();

            b.iter(|| {
                black_box({
                    // Agent 0 creates the agreement
                    let agreement = agents[0]
                        .0
                        .create_agreement(&doc_str, &agent_ids, Some("Do you agree?"), None)
                        .expect("create_agreement");

                    // Each agent signs in sequence
                    let mut current_doc = agreement.raw;
                    for (agent, _) in &agents {
                        let signed = agent.sign_agreement(&current_doc).expect("sign_agreement");
                        current_doc = signed.raw;
                    }

                    // Verify the final agreement
                    agents[0]
                        .0
                        .check_agreement(&current_doc)
                        .expect("check_agreement");
                });
            });
        });
    }
    group.finish();
}

/// Benchmark: concurrent signing from N SimpleAgent instances.
fn bench_concurrent_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_sign");

    for n in [10, 50, 100] {
        group.bench_with_input(BenchmarkId::new("agents", n), &n, |b, &n| {
            // Pre-create agents (setup, not measured)
            let agents: Vec<Arc<SimpleAgent>> = (0..n)
                .map(|_| {
                    let (agent, _) = SimpleAgent::ephemeral(Some("ed25519"))
                        .expect("Failed to create ephemeral agent");
                    Arc::new(agent)
                })
                .collect();
            let data = json!({"action": "benchmark", "concurrent": true});

            b.iter(|| {
                black_box({
                    let handles: Vec<_> = agents
                        .iter()
                        .map(|agent| {
                            let agent = Arc::clone(agent);
                            let data = data.clone();
                            thread::spawn(move || {
                                let signed = agent.sign_message(&data).unwrap();
                                agent.verify(&signed.raw).unwrap();
                            })
                        })
                        .collect();

                    for handle in handles {
                        handle.join().expect("thread panicked");
                    }
                });
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = configure_criterion();
    targets = bench_agreement_n_party, bench_concurrent_signing
}
criterion_main!(benches);
