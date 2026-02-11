use criterion::{Criterion, black_box, criterion_group, criterion_main};
use jacs::agent::Agent;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::simple::SimpleAgent;
use log::debug;
use serde_json::json;

use jacs::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
use jacs::storage::jenv::set_env_var;
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

fn set_enc_to_ring() {
    set_env_var(
        "JACS_AGENT_PRIVATE_KEY_FILENAME",
        "test-ring-Ed25519-private.pem",
    )
    .expect("Failed to set private key filename");
    set_env_var(
        "JACS_AGENT_PUBLIC_KEY_FILENAME",
        "test-ring-Ed25519-public.pem",
    )
    .expect("Failed to set public key filename");
    set_env_var("JACS_AGENT_KEY_ALGORITHM", "ring-Ed25519").expect("Failed to set key algorithm");
}

fn set_enc_to_pq() {
    set_env_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "test-pq-private.pem")
        .expect("Failed to set private key filename");
    set_env_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "test-pq-public.pem")
        .expect("Failed to set public key filename");
    set_env_var("JACS_AGENT_KEY_ALGORITHM", "pq-dilithium").expect("Failed to set key algorithm");
}

fn load_test_agent_one() -> Agent {
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();

    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let agentid =
        "0f6bb6e8-f27c-4cf7-bb2e-01b647860680:a55739af-a3c8-4b4a-9f24-200313ee4229".to_string();
    let result = agent.load_by_id(agentid);
    match result {
        Ok(_) => {
            debug!(
                "AGENT ONE LOADED {} {} ",
                agent.get_id().unwrap(),
                agent.get_version().unwrap()
            );
        }
        Err(e) => {
            eprintln!("Error loading agent: {}", e);
            panic!("Agent loading failed");
        }
    }
    agent
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

fn benchmark_rsa(c: &mut Criterion) {
    let documents = generate_synthetic_data(BENCH_SAMPLE_SIZE);
    let mut agent = load_test_agent_one();
    c.bench_function("rsa", |b| {
        for document in &documents {
            b.iter(|| {
                black_box({
                    let jacsdocument = agent
                        .create_document_and_load(&document, None, None)
                        .unwrap();
                    let document_key = jacsdocument.getkey();
                    agent
                        .verify_document_signature(
                            &document_key,
                            Some(&DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string()),
                            None,
                            None,
                            None,
                        )
                        .unwrap();
                });
            })
        }
    });
}

fn benchmark_pq(c: &mut Criterion) {
    set_enc_to_pq();
    let mut agent2 = load_test_agent_one();
    let documents = generate_synthetic_data(BENCH_SAMPLE_SIZE);
    c.bench_function("pq", |b| {
        for document in &documents {
            b.iter(|| {
                black_box({
                    let jacsdocument = agent2
                        .create_document_and_load(&document, None, None)
                        .unwrap();
                    let document_key = jacsdocument.getkey();
                    agent2
                        .verify_document_signature(
                            &document_key,
                            Some(&DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string()),
                            None,
                            None,
                            None,
                        )
                        .unwrap();
                });
            })
        }
    });
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

fn benchmark_ring(c: &mut Criterion) {
    set_enc_to_ring();
    let documents = generate_synthetic_data(BENCH_SAMPLE_SIZE);
    let mut agent3 = load_test_agent_one();
    c.bench_function("ring", |b| {
        for document in &documents {
            b.iter(|| {
                black_box({
                    let jacsdocument = agent3
                        .create_document_and_load(&document, None, None)
                        .unwrap();
                    let document_key = jacsdocument.getkey();
                    agent3
                        .verify_document_signature(
                            &document_key,
                            Some(&DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string()),
                            None,
                            None,
                            None,
                        )
                        .unwrap();
                });
            })
        }
    });
}

criterion_group! {
    name = benches;
    config = configure_criterion();
    targets = benchmark_rsa, benchmark_pq, benchmark_pq2025, benchmark_ring
}
criterion_main!(benches);
