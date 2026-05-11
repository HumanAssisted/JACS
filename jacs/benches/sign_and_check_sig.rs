use criterion::{Criterion, black_box, criterion_group, criterion_main};
use jacs::simple::SimpleAgent;

use rand::distr::Alphanumeric;
use rand::prelude::*;

static BENCH_SAMPLE_SIZE: usize = 100;

fn configure_criterion() -> Criterion {
    Criterion::default()
        .sample_size(50) // Number of samples to collect
        .measurement_time(std::time::Duration::from_secs(10)) // Time spent measuring each sample
        .confidence_level(0.95) // Statistical confidence level
        .noise_threshold(0.05) // Noise threshold for detecting performance changes
}

/// JSON with arbitrary keys from 2-20 keys, with data of string length from 10-250. (random length )
fn generate_synthetic_data(count: usize) -> Vec<String> {
    let mut rng = rand::rng();
    let mut documents = Vec::with_capacity(count);

    for i in 0..count {
        let num_keys = rng.random_range(2..=20);
        let mut document = format!("{{\"id\": {}", i);

        for _ in 1..num_keys {
            let key_length = rng.random_range(5..=20);
            let key: String = std::iter::repeat_with(|| rng.sample(Alphanumeric))
                .map(char::from)
                .take(key_length)
                .collect();

            let value_length = rng.random_range(10..=250);
            let value: String = std::iter::repeat_with(|| rng.sample(Alphanumeric))
                .map(char::from)
                .take(value_length)
                .collect();

            document.push_str(&format!(",\"{}\": \"{}\"", key, value));
        }

        document.push('}');
        documents.push(document);
    }

    documents
}

fn benchmark_pq2025(c: &mut Criterion) {
    // Use SimpleAgent::ephemeral to create a pq2025 agent with in-memory keys
    let (agent, _info) =
        SimpleAgent::ephemeral(Some("pq2025")).expect("Failed to create ephemeral pq2025 agent");
    let documents = generate_synthetic_data(BENCH_SAMPLE_SIZE);
    c.bench_function("pq2025", |b| {
        for document in &documents {
            let data: serde_json::Value = serde_json::from_str(document).unwrap();
            b.iter(|| {
                black_box({
                    let signed = agent.sign_message(&data).unwrap();
                    agent.verify(&signed.raw).unwrap();
                });
            })
        }
    });
}

fn benchmark_ed25519(c: &mut Criterion) {
    let (agent, _info) = SimpleAgent::ephemeral(Some("ring-Ed25519"))
        .expect("Failed to create ephemeral Ed25519 agent");
    let documents = generate_synthetic_data(BENCH_SAMPLE_SIZE);
    c.bench_function("ed25519", |b| {
        for document in &documents {
            let data: serde_json::Value = serde_json::from_str(document).unwrap();
            b.iter(|| {
                black_box({
                    let signed = agent.sign_message(&data).unwrap();
                    agent.verify(&signed.raw).unwrap();
                });
            })
        }
    });
}

criterion_group! {
    name = benches;
    config = configure_criterion();
    targets = benchmark_ed25519, benchmark_pq2025
}
criterion_main!(benches);
