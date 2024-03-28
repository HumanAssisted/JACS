use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::loaders::FileLoader;
use jacs::agent::Agent;
use log::debug;

use jacs::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
use rand::Rng;
use std::env;

fn set_enc_to_ring() {
    env::set_var(
        "JACS_AGENT_PRIVATE_KEY_FILENAME",
        "test-ring-Ed25519-private.pem",
    );
    env::set_var(
        "JACS_AGENT_PUBLIC_KEY_FILENAME",
        "test-ring-Ed25519-public.pem",
    );
    env::set_var("JACS_AGENT_KEY_ALGORITHM", "ring-Ed25519");
}

fn set_enc_to_pq() {
    env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "test-pq-private.pem");
    env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "test-pq-public.pem");
    env::set_var("JACS_AGENT_KEY_ALGORITHM", "pq-dilithium");
}

fn load_test_agent_one() -> Agent {
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();

    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let agentid =
        "fe00bb15-8c7f-43ac-9413-5a7bd5bb039d:1f639f69-b3a7-45d5-b814-bc7b91fb3b97".to_string();
    let result = agent.load_by_id(agentid, None);
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
    let mut rng = rand::thread_rng();
    let mut documents = Vec::with_capacity(count);

    for i in 0..count {
        let num_keys = rng.gen_range(2..=20);
        let mut document = format!("{{\"id\": {}", i);

        for j in 1..num_keys {
            let key_length = rng.gen_range(5..=20);
            let key: String = rng
                .clone()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(key_length)
                .map(char::from)
                .collect();

            let value_length = rng.gen_range(10..=250);
            let value: String = rng
                .clone()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(value_length)
                .map(char::from)
                .collect();

            document.push_str(&format!(",\"{}\": \"{}\"", key, value));
        }

        document.push('}');
        documents.push(document);
    }

    documents
}

fn benchmark_function(c: &mut Criterion) {
    let documents = generate_synthetic_data(1000);
    let mut count = 0;
    let mut agent = load_test_agent_one();
    c.bench_function("rsa", |b| {
        b.iter(|| {
            count = 0;
            for document in &documents {
                black_box({
                    count += 1;
                    let jacsdocument = agent.create_document_and_load(&document).unwrap();
                    let document_key = jacsdocument.getkey();
                    agent
                        .verify_document_signature(
                            &document_key,
                            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
                            None,
                            None,
                        )
                        .unwrap();
                });
            }
        })
    });

    c.bench_function("pq", |b| {
        set_enc_to_pq();
        b.iter(|| {
            for document in &documents {
                count = 0;
                black_box({
                    count += 1;
                    let jacsdocument = agent.create_document_and_load(&document).unwrap();
                    let document_key = jacsdocument.getkey();
                    agent
                        .verify_document_signature(
                            &document_key,
                            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
                            None,
                            None,
                        )
                        .unwrap();
                });
            }
        })
    });

    c.bench_function("ring", |b| {
        set_enc_to_ring();
        b.iter(|| {
            for document in &documents {
                count = 0;
                black_box({
                    count += 1;
                    let jacsdocument = agent.create_document_and_load(&document).unwrap();
                    let document_key = jacsdocument.getkey();
                    agent
                        .verify_document_signature(
                            &document_key,
                            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
                            None,
                            None,
                        )
                        .unwrap();
                });
            }
        })
    });
}

criterion_group!(benches, benchmark_function);
criterion_main!(benches);
