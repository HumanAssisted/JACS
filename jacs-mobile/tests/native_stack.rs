//! Exercise the synchronous facade on native-sized caller stacks. Each probe
//! runs in a child process because Rust stack overflows abort the process.
//! Run with `cargo test -p jacs-mobile --release --test native_stack` to measure
//! production optimization; unoptimized cryptography has a different stack bound.

#![cfg(not(debug_assertions))]

use jacs_mobile::MobileAgent;
use std::process::Command;

#[test]
fn pq_operations_on_small_caller_stacks() {
    let mut failures = Vec::new();
    for stack_bytes in [512 * 1024, 1024 * 1024] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "small_stack_child", "--ignored", "--nocapture"])
            .env("JACS_MOBILE_PROBE_STACK_BYTES", stack_bytes.to_string())
            .output()
            .unwrap();
        if !output.status.success() {
            failures.push(format!(
                "PQ operations failed with {stack_bytes} bytes of caller stack ({}):\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ));
        }
        println!(
            "PQ caller stack {stack_bytes} bytes:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore = "subprocess probe; invoked by pq_operations_on_small_caller_stacks"]
fn small_stack_child() {
    let stack_bytes: usize = std::env::var("JACS_MOBILE_PROBE_STACK_BYTES")
        .expect("probe stack must be explicitly configured")
        .parse()
        .unwrap();
    std::thread::Builder::new()
        .name("mobile-caller".into())
        .stack_size(stack_bytes)
        .spawn(|| {
            println!("create default PQ");
            let agent = MobileAgent::create_default().unwrap();
            println!("sign JSON");
            let signed = agent
                .sign_message_json(r#"{"probe":"native-stack"}"#.into())
                .unwrap();
            println!("verify JSON");
            assert!(agent.verify_json(signed.clone()).unwrap().valid);
            println!("export encrypted material");
            let password = "Native-stack-test-only-password!".to_string();
            let material = agent.export_encrypted_agent(password.clone()).unwrap();
            agent.clear_secrets().unwrap();
            println!("import encrypted material");
            let restored = MobileAgent::import_encrypted_agent(material, password).unwrap();
            assert!(restored.verify_json(signed).unwrap().valid);
            println!("sign after import");
            let signed = restored
                .sign_message_json(r#"{"probe":"restored"}"#.into())
                .unwrap();
            assert!(restored.verify_json(signed).unwrap().valid);
            restored.clear_secrets().unwrap();
            println!("human creation and generated recovery");
            let human = MobileAgent::create_human().unwrap();
            let identity: serde_json::Value =
                serde_json::from_str(&human.export_agent_json().unwrap()).unwrap();
            let recovery = human.export_recovery().unwrap();
            let recovered = MobileAgent::import_recovery(
                recovery.material,
                recovery.code,
                identity["jacsId"].as_str().unwrap().into(),
                human.public_key().unwrap(),
                jacs_mobile::MobileAlgorithm::Pq2025,
            )
            .unwrap();
            assert_eq!(
                human.export_agent_json().unwrap(),
                recovered.export_agent_json().unwrap()
            );
            let complete = human
                .sign_document_json(r#"{"stack":"full-document"}"#.into())
                .unwrap();
            assert!(recovered.verify_json(complete).unwrap().valid);
            let readback = human.export_recovery().unwrap();
            assert_eq!(
                jacs_mobile::verify_recovery(
                    readback.material,
                    readback.code,
                    identity["jacsId"].as_str().unwrap().into(),
                    human.public_key().unwrap(),
                    jacs_mobile::MobileAlgorithm::Pq2025
                )
                .unwrap(),
                human.export_agent_json().unwrap()
            );
            println!("staged rotation, candidate proof/recovery and commit");
            let password = "Native-stack-rotation-test-only!".to_string();
            let stage = human.prepare_key_rotation(password.clone()).unwrap();
            let proof = human
                .sign_rotation_document_json(stage.clone(), password.clone(), "{}".into())
                .unwrap();
            assert!(
                jacs_mobile::verify_with_key(
                    proof,
                    stage.public_key.clone(),
                    jacs_mobile::MobileAlgorithm::Pq2025
                )
                .unwrap()
                .valid
            );
            let recovery = human
                .export_rotation_recovery(stage.clone(), password.clone())
                .unwrap();
            assert!(!recovery.material.encrypted_private_key.is_empty());
            human
                .commit_key_rotation(stage.clone(), password, stage.agent_json, stage.public_key)
                .unwrap();
            human.clear_secrets().unwrap();
            recovered.clear_secrets().unwrap();
            println!("complete");
        })
        .unwrap()
        .join()
        .unwrap();
}
