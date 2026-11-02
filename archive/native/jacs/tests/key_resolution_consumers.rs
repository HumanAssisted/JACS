//! Public consumers resolve exact foreign/historical keys without network access.

use jacs::agent::{Agent, boilerplate::BoilerPlate, document::DocumentTraits, loaders::FileLoader};
use jacs::crypt::hash::hash_public_key;
use jacs::simple::SimpleAgent;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

struct LocalOnly {
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    _directory: tempfile::TempDir,
}

impl LocalOnly {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let previous = ["JACS_KEY_RESOLUTION", "JACS_TRUST_STORE_DIR"]
            .into_iter()
            .map(|name| (name, std::env::var_os(name)))
            .collect();
        unsafe {
            std::env::set_var("JACS_KEY_RESOLUTION", "local");
            std::env::set_var("JACS_TRUST_STORE_DIR", directory.path());
        }
        Self {
            previous,
            _directory: directory,
        }
    }
}

impl Drop for LocalOnly {
    fn drop(&mut self) {
        for (name, value) in &self.previous {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

fn identity() -> (Arc<Mutex<Agent>>, SimpleAgent) {
    let mut agent = Agent::ephemeral("pq2025").unwrap();
    agent.create_agent_and_load(
        &json!({"jacsAgentType":"ai", "name":"resolver-consumer", "description":"Local verification test"}).to_string(),
        true,
        Some("pq2025"),
    ).unwrap();
    let shared = Arc::new(Mutex::new(agent));
    let simple = SimpleAgent::from_shared_agent(shared.clone(), None, false);
    (shared, simple)
}

fn cache(agent: &Agent, claimed_hash: &str, key: &[u8]) {
    agent
        .fs_save_remote_public_key(claimed_hash, key, b"pq2025")
        .unwrap();
}

fn rehash(agent: &Agent, value: &mut Value) {
    value["jacsSha256"] = json!(agent.hash_doc(value).unwrap());
}

#[test]
#[serial_test::serial(jacs_env, home_env)]
fn json_and_mime_resolve_foreign_and_historical_keys_without_self_key_confusion() {
    let _environment = LocalOnly::new();
    let (signer, sender) = identity();
    let (receiver, recipient) = identity();
    let signed = sender.sign_message(&json!({"score": 7})).unwrap();
    let document: Value = serde_json::from_str(&signed.raw).unwrap();
    let key = signer.lock().unwrap().get_public_key().unwrap();
    let hash = document["jacsSignature"]["publicKeyHash"].as_str().unwrap();
    assert!(!recipient.verify(&signed.raw).unwrap().valid);
    cache(&receiver.lock().unwrap(), hash, &key);
    assert!(recipient.verify(&signed.raw).unwrap().valid);
    assert!(
        recipient
            .verify_with_mime(&signed.raw, "application/json")
            .unwrap()
            .valid
    );

    // Recompute the public document hash so rejection requires signature checks.
    let mut tampered = document.clone();
    tampered["content"]["score"] = json!(8);
    rehash(&signer.lock().unwrap(), &mut tampered);
    assert!(!recipient.verify(&tampered.to_string()).unwrap().valid);

    let wrong = receiver.lock().unwrap().get_public_key().unwrap();
    cache(&receiver.lock().unwrap(), hash, &wrong);
    assert!(
        !recipient
            .verify_with_mime(&signed.raw, "application/json")
            .unwrap()
            .valid
    );
    cache(&receiver.lock().unwrap(), hash, &key);
    assert!(recipient.verify(&signed.raw).unwrap().valid);

    let old_version = document["jacsSignature"]["agentVersion"].as_str().unwrap();
    let mut native = signer.lock().unwrap();
    let (new_version, new_key, _) = native.rotate_self(Some("pq2025")).unwrap();
    assert_ne!(new_version, old_version);
    assert_ne!(new_key, key);
    drop(native);
    // Creation cached the original key; rotation must still resolve it.
    assert!(sender.verify(&signed.raw).unwrap().valid);
    // UUID equality must not make the new self key authoritative for old bytes.
    cache(&signer.lock().unwrap(), hash, &new_key);
    assert!(!sender.verify(&signed.raw).unwrap().valid);
    cache(&signer.lock().unwrap(), hash, &key);
    assert!(sender.verify(&signed.raw).unwrap().valid);
    assert!(
        sender
            .verify_with_mime(&signed.raw, "application/json")
            .unwrap()
            .valid
    );
}

#[test]
#[serial_test::serial(jacs_env, home_env)]
fn full_jacs_text_and_image_consumers_share_foreign_key_resolution() {
    use jacs::simple::advanced::{sign_image, sign_text_file, verify_image};
    use jacs::simple::types::{
        MediaVerifyStatus, SignImageOptions, SignTextOptions, VerifyImageOptions,
    };
    let _environment = LocalOnly::new();
    let (signer, sender) = identity();
    let (receiver, recipient) = identity();
    let directory = tempfile::tempdir().unwrap();
    let text = directory.path().join("report.md");
    std::fs::write(&text, "# Report\n\nThe score is seven.\n").unwrap();
    sign_text_file(&sender, text.to_str().unwrap(), SignTextOptions::default()).unwrap();
    let framed = std::fs::read_to_string(&text).unwrap();

    let input = directory.path().join("input.png");
    let output = directory.path().join("signed.png");
    image::RgbaImage::from_pixel(16, 16, image::Rgba([32, 64, 128, 255]))
        .save(&input)
        .unwrap();
    sign_image(
        &sender,
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        SignImageOptions::default(),
    )
    .unwrap();
    assert!(
        !recipient
            .verify_with_mime(&framed, "text/markdown")
            .unwrap()
            .valid
    );
    assert_ne!(
        verify_image(
            &recipient,
            output.to_str().unwrap(),
            VerifyImageOptions::default()
        )
        .unwrap()
        .status,
        MediaVerifyStatus::Valid
    );

    let key = signer.lock().unwrap().get_public_key().unwrap();
    let hash = hash_public_key(&key);
    cache(&receiver.lock().unwrap(), &hash, &key);
    assert!(recipient.verify(&framed).unwrap().valid);
    assert!(
        recipient
            .verify_with_mime(&framed, "text/markdown")
            .unwrap()
            .valid
    );
    assert_eq!(
        verify_image(
            &recipient,
            output.to_str().unwrap(),
            VerifyImageOptions::default()
        )
        .unwrap()
        .status,
        MediaVerifyStatus::Valid
    );
    assert!(
        !recipient
            .verify_with_mime(&framed.replacen("seven", "eight", 1), "text/markdown")
            .unwrap()
            .valid
    );

    let wrong = receiver.lock().unwrap().get_public_key().unwrap();
    cache(&receiver.lock().unwrap(), &hash, &wrong);
    assert!(!recipient.verify(&framed).unwrap().valid);
    assert_ne!(
        verify_image(
            &recipient,
            output.to_str().unwrap(),
            VerifyImageOptions::default()
        )
        .unwrap()
        .status,
        MediaVerifyStatus::Valid
    );
}

#[test]
#[cfg(feature = "a2a")]
#[serial_test::serial(jacs_env, home_env)]
fn a2a_artifact_consumer_resolves_foreign_and_historical_roots() {
    use jacs::a2a::provenance::{verify_wrapped_artifact, wrap_artifact_with_provenance};
    let _environment = LocalOnly::new();
    let (signer, _) = identity();
    let (receiver, _) = identity();
    let wrapped = wrap_artifact_with_provenance(
        &mut signer.lock().unwrap(),
        json!({"messageId":"message-1", "content":"seven"}),
        "message",
        None,
    )
    .unwrap();
    let key = signer.lock().unwrap().get_public_key().unwrap();
    let hash = wrapped["jacsSignature"]["publicKeyHash"].as_str().unwrap();
    assert!(
        !verify_wrapped_artifact(&receiver.lock().unwrap(), &wrapped)
            .unwrap()
            .valid
    );
    cache(&receiver.lock().unwrap(), hash, &key);
    assert!(
        verify_wrapped_artifact(&receiver.lock().unwrap(), &wrapped)
            .unwrap()
            .valid
    );
    let mut tampered = wrapped.clone();
    tampered["a2aArtifact"]["content"] = json!("eight");
    rehash(&signer.lock().unwrap(), &mut tampered);
    assert!(
        !verify_wrapped_artifact(&receiver.lock().unwrap(), &tampered)
            .unwrap()
            .valid
    );
    let wrong = receiver.lock().unwrap().get_public_key().unwrap();
    cache(&receiver.lock().unwrap(), hash, &wrong);
    assert!(
        !verify_wrapped_artifact(&receiver.lock().unwrap(), &wrapped)
            .unwrap()
            .valid
    );

    let (_, new_key, _) = signer.lock().unwrap().rotate_self(Some("pq2025")).unwrap();
    assert!(
        verify_wrapped_artifact(&signer.lock().unwrap(), &wrapped)
            .unwrap()
            .valid
    );
    cache(&signer.lock().unwrap(), hash, &new_key);
    assert!(
        !verify_wrapped_artifact(&signer.lock().unwrap(), &wrapped)
            .unwrap()
            .valid
    );
    cache(&signer.lock().unwrap(), hash, &key);
    assert!(
        verify_wrapped_artifact(&signer.lock().unwrap(), &wrapped)
            .unwrap()
            .valid
    );
}

#[test]
#[cfg(feature = "attestation")]
#[serial_test::serial(jacs_env, home_env)]
fn attestation_consumer_checks_foreign_signature_with_exact_cached_key() {
    use jacs::attestation::simple;
    let _environment = LocalOnly::new();
    let (signer, sender) = identity();
    let (receiver, recipient) = identity();
    let signed = simple::create_from_json(
        &sender,
        &json!({
            "subject":{"type":"artifact", "id":"report-1", "digests":{"sha256":"abc123def456"}},
            "claims":[{"name":"reviewed", "value":true}]
        })
        .to_string(),
    )
    .unwrap();
    let document: Value = serde_json::from_str(&signed.raw).unwrap();
    let imported = receiver.lock().unwrap().load_document(&signed.raw).unwrap();
    let document_key = format!("{}:{}", imported.id, imported.version);
    let key = signer.lock().unwrap().get_public_key().unwrap();
    let hash = document["jacsSignature"]["publicKeyHash"].as_str().unwrap();
    assert!(!simple::verify(&recipient, &document_key).unwrap().valid);
    cache(&receiver.lock().unwrap(), hash, &key);
    let verified = simple::verify(&recipient, &document_key).unwrap();
    assert!(verified.valid && verified.crypto.signature_valid && verified.crypto.hash_valid);
    let wrong = receiver.lock().unwrap().get_public_key().unwrap();
    cache(&receiver.lock().unwrap(), hash, &wrong);
    let rejected = simple::verify(&recipient, &document_key).unwrap();
    assert!(!rejected.valid && !rejected.crypto.signature_valid && rejected.crypto.hash_valid);
    cache(&receiver.lock().unwrap(), hash, &key);
    let mut tampered = document.clone();
    tampered["attestation"]["claims"][0]["value"] = json!(false);
    rehash(&signer.lock().unwrap(), &mut tampered);
    // Evict only this test's imported immutable copy, then verify the submitted
    // tampered bytes rather than accidentally rechecking the original version.
    use jacs::storage::StorageDocumentTraits as _;
    let mut native = receiver.lock().unwrap();
    native.storage_ref().remove_document(&document_key).unwrap();
    native.store_jacs_document(&tampered).unwrap();
    drop(native);
    let rejected = simple::verify(&recipient, &document_key).unwrap();
    assert!(!rejected.valid && !rejected.crypto.signature_valid && rejected.crypto.hash_valid);
}
