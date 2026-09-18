//! Real JSON-lines protocol tests against Cargo's built portable CLI.
//! No same-SDK client, installed executable, private fixture, or ambient grant.
#![cfg(unix)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use jacs_core::{AgentMaterial, SigningAlgorithm};
use jacs_mcp::vault;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PASSWORD: &str = "synthetic-stdio-only-password-8VmKp";
const PRIVATE_MARKER: &str = "synthetic-private-content-marker";

struct Fixture {
    directory: tempfile::TempDir,
    material: AgentMaterial,
    signed: Value,
}

impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let material = vault::create_material(SigningAlgorithm::Pq2025, PASSWORD).unwrap();
        vault::write_material(&directory.path().join("agent.json"), &material).unwrap();
        let signed = vault::unlock(&material, PASSWORD)
            .unwrap()
            .sign_message(&json!({"message":"public-stdio-fixture"}))
            .unwrap();
        Self {
            directory,
            material,
            signed,
        }
    }

    fn verify_args(&self, document: &Value) -> Value {
        json!({"document":document.to_string(), "public_key":STANDARD.encode(&self.material.public_key), "algorithm":"pq2025"})
    }
}

struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    responses: mpsc::Receiver<Value>,
    stderr: Arc<Mutex<Vec<u8>>>,
    readers: Vec<JoinHandle<()>>,
}

impl Session {
    fn start(directory: &Path, local: bool, ambient_authority: bool) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_jacs"));
        command
            .arg("mcp")
            .current_dir(directory)
            .env("RUST_LOG", "warn")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("JACS_") {
                command.env_remove(name);
            }
        }
        if local {
            command
                .args(["--profile", "local-sign", "--agent"])
                .arg(directory.join("agent.json"))
                .env("JACS_PRIVATE_KEY_PASSWORD", PASSWORD);
        }
        if ambient_authority {
            command
                .env("JACS_CONFIG", directory.join("agent.json"))
                .env("JACS_MCP_PROFILE", "local-sign")
                .env(
                    "JACS_PRIVATE_KEY_PASSWORD",
                    "synthetic-unusable-ambient-password",
                );
        }
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let mut diagnostic = child.stderr.take().unwrap();
        let (sender, responses) = mpsc::channel();
        let stdout_reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let frame = jacs_core::strict_json::parse_strict_json(&line)
                    .expect("MCP stdout must contain only unambiguous JSON frames");
                if sender.send(frame).is_err() {
                    break;
                }
            }
        });
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let captured = stderr.clone();
        let stderr_reader = thread::spawn(move || {
            let mut bytes = [0; 4096];
            while let Ok(count) = diagnostic.read(&mut bytes) {
                if count == 0 {
                    break;
                }
                captured.lock().unwrap().extend_from_slice(&bytes[..count]);
            }
        });
        Self {
            child,
            stdin,
            responses,
            stderr,
            readers: vec![stdout_reader, stderr_reader],
        }
    }

    fn send(&mut self, frame: &Value) {
        let stdin = self.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *stdin, frame).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    fn request(&mut self, frame: Value) -> Value {
        let id = frame["id"].clone();
        self.send(&frame);
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let response = self
                .responses
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("MCP response missing, closed, or not valid JSON");
            assert_eq!(response["jsonrpc"], "2.0");
            if response.get("id") == Some(&id) {
                assert_ne!(
                    response.get("result").is_some(),
                    response.get("error").is_some()
                );
                return response;
            }
        }
    }

    fn wait_for_log(&self, marker: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let log = String::from_utf8(self.stderr.lock().unwrap().clone()).unwrap();
            if log.contains(marker) {
                return log;
            }
            assert!(
                Instant::now() < deadline,
                "Missing expected diagnostic event: {marker}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn shutdown(&mut self) {
        self.stdin.take();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "MCP must shut down cleanly after stdin EOF"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "MCP did not stop after stdin EOF"
            );
            thread::sleep(Duration::from_millis(10));
        }
        for reader in self.readers.drain(..) {
            reader.join().unwrap();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

fn modern(id: u64, method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"portable-stdio-test","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{}
    });
    json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params})
}

fn call(id: u64, name: &str, args: Value) -> Value {
    modern(id, "tools/call", json!({"name":name,"arguments":args}))
}

fn result(response: &Value) -> &Value {
    assert!(response.get("error").is_none(), "Unexpected JSON-RPC error");
    &response["result"]
}

fn payload(response: &Value) -> Value {
    let result = result(response);
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["isError"], false);
    serde_json::from_str(
        result["content"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["type"] == "text")
            .unwrap()["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}

fn invalid_params(response: &Value) {
    assert!(response.get("result").is_none());
    assert_eq!(response["error"]["code"], -32602);
}

fn listed_names(response: &Value) -> Vec<&str> {
    result(response)["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect()
}

#[test]
fn legacy_initialization_keeps_legacy_shape_and_verification_only() {
    let directory = tempfile::tempdir().unwrap();
    let mut session = Session::start(directory.path(), false, false);
    let initialized = session.request(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"legacy-test","version":"1"}
    }}));
    assert_eq!(result(&initialized)["protocolVersion"], "2025-11-25");
    assert_eq!(result(&initialized)["serverInfo"]["name"], "jacs-mcp");
    session.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let listed = session.request(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}));
    assert!(result(&listed).get("resultType").is_none());
    assert_eq!(listed_names(&listed), ["jacs_verify_document"]);
    session.shutdown();
}

#[test]
fn modern_discovery_recovers_after_protocol_and_metadata_rejection() {
    let directory = tempfile::tempdir().unwrap();
    let mut session = Session::start(directory.path(), false, false);
    let mut unsupported = modern(1, "server/discover", json!({}));
    unsupported["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2099-01-01");
    let rejected = session.request(unsupported);
    assert_eq!(rejected["error"]["code"], -32022);
    assert_eq!(rejected["error"]["data"]["requested"], "2099-01-01");
    let discovered = session.request(modern(2, "server/discover", json!({})));
    assert_eq!(result(&discovered)["resultType"], "complete");
    assert!(
        result(&discovered)["supportedVersions"]
            .as_array()
            .unwrap()
            .contains(&json!("2026-07-28"))
    );
    let mut malformed = modern(3, "tools/list", json!({}));
    malformed["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
        json!("not-an-object");
    invalid_params(&session.request(malformed));
    let recovered = session.request(modern(4, "server/discover", json!({})));
    assert_eq!(
        result(&recovered)["supportedVersions"],
        result(&discovered)["supportedVersions"]
    );
    let listed = session.request(modern(5, "tools/list", json!({})));
    assert_eq!(result(&listed)["resultType"], "complete");
    assert_eq!(listed_names(&listed), ["jacs_verify_document"]);
    session.shutdown();
}

#[test]
fn pq_local_signing_preserves_caller_data_and_recovers_after_tampering() {
    let fixture = Fixture::new();
    let mut session = Session::start(fixture.directory.path(), true, false);
    let discovered = session.request(modern(1, "server/discover", json!({})));
    assert_eq!(result(&discovered)["resultType"], "complete");
    let listed = session.request(modern(2, "tools/list", json!({})));
    assert_eq!(listed_names(&listed), jacs_mcp::contract::TOOL_NAMES);
    let signing_description = result(&listed)["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "jacs_sign_document")
        .unwrap()["description"]
        .as_str()
        .unwrap();
    assert!(signing_description.contains("not human approval"));
    for (index, arguments) in [
        json!({"document":42}),
        json!({"document":"{}", "private-sign-argument-marker":true}),
        json!({"document":"{private-sign-content-marker"}),
    ]
    .into_iter()
    .enumerate()
    {
        let rejected = session.request(call(30 + index as u64, "jacs_sign_document", arguments));
        invalid_params(&rejected);
        assert!(!rejected.to_string().contains("private-sign-"));
    }
    let supplied = json!({"jacsType":"agent", "jacsLevel":"config", "jacsId":"caller-identity-marker",
        "jacsSignature":{"agentID":"caller-signer-marker"}, "jacsVisibility":"public",
        "_jacs_meta":{"hint":"permission-to-publish-marker"}, "humanApproval":true, "message":PRIVATE_MARKER});
    let signed = payload(&session.request(call(
        3,
        "jacs_sign_document",
        json!({"document":supplied.to_string()}),
    )));
    assert_eq!(signed["algorithm"], "pq2025");
    let document = &signed["document"];
    assert_eq!(document["content"], supplied);
    assert_eq!(document["jacsType"], "message");
    assert_eq!(document["jacsLevel"], "raw");
    assert_eq!(
        document["jacsSignature"]["agentID"],
        fixture.material.agent["jacsId"]
    );
    assert_ne!(document["jacsId"], supplied["jacsId"]);
    assert!(document.get("humanApproval").is_none());
    assert!(document.get("_jacs_meta").is_none());
    let verified = payload(&session.request(call(
        4,
        "jacs_verify_document",
        fixture.verify_args(document),
    )));
    assert_eq!(verified["valid"], true);
    let mut tampered = document.clone();
    tampered["content"]["message"] = json!("tampered-private-marker");
    let denied = payload(&session.request(call(
        5,
        "jacs_verify_document",
        fixture.verify_args(&tampered),
    )));
    assert_eq!(denied["valid"], false);
    let recovered = payload(&session.request(call(
        6,
        "jacs_verify_document",
        fixture.verify_args(document),
    )));
    assert_eq!(recovered["valid"], true);
    let logs = session.wait_for_log("mcp_verification_failed");
    assert!(logs.contains("WARN"));
    for marker in [
        PASSWORD,
        PRIVATE_MARKER,
        "tampered-private-marker",
        "caller-signer-marker",
        "permission-to-publish-marker",
        "private-sign-argument-marker",
        "private-sign-content-marker",
    ] {
        assert!(!logs.contains(marker), "Private marker appeared in stderr");
    }
    session.shutdown();
}

#[test]
fn scope_and_verification_errors_are_redacted_and_recoverable() {
    let fixture = Fixture::new();
    let mut session = Session::start(fixture.directory.path(), false, false);
    result(&session.request(modern(1, "server/discover", json!({}))));
    for (id, name) in [
        (2, "jacs_sign_document"),
        (3, "unknown-private-tool-marker"),
    ] {
        let rejected = session.request(call(id, name, json!({"document":PRIVATE_MARKER})));
        invalid_params(&rejected);
        assert!(!rejected.to_string().contains(PRIVATE_MARKER));
        assert!(!rejected.to_string().contains("unknown-private-tool-marker"));
    }
    let mut wrong_key = fixture.verify_args(&fixture.signed);
    wrong_key["public_key"] = json!("private-key-input-marker!");
    let mut wrong_algorithm = fixture.verify_args(&fixture.signed);
    wrong_algorithm["algorithm"] = json!("private-algorithm-marker");
    let mut malformed = fixture.verify_args(&fixture.signed);
    malformed["document"] = json!("{private-malformed-document-marker");
    let mut malformed_signature = fixture.signed.clone();
    malformed_signature["jacsSignature"]["signingAlgorithm"] =
        json!("private-signature-algorithm-marker");
    for (index, args) in [
        json!({"private-argument-marker":true}),
        malformed,
        wrong_key,
        wrong_algorithm,
        fixture.verify_args(&malformed_signature),
    ]
    .into_iter()
    .enumerate()
    {
        let rejected = session.request(call(4 + index as u64, "jacs_verify_document", args));
        invalid_params(&rejected);
        assert!(!rejected.to_string().contains("private-"));
    }
    let recovered = payload(&session.request(call(
        20,
        "jacs_verify_document",
        fixture.verify_args(&fixture.signed),
    )));
    assert_eq!(recovered["valid"], true);
    session.wait_for_log("verification_rejected");
    session.shutdown();
    let logs = String::from_utf8(session.stderr.lock().unwrap().clone()).unwrap();
    for marker in [
        PRIVATE_MARKER,
        PASSWORD,
        "unknown-private-tool-marker",
        "private-argument-marker",
        "private-key-input-marker",
        "private-algorithm-marker",
        "private-malformed-document-marker",
        "private-signature-algorithm-marker",
    ] {
        assert!(
            !logs.contains(marker),
            "Rejected client input appeared in stderr"
        );
    }
    for event in [
        "mcp_tool_scope_denied",
        "mcp_verification_failed",
        "invalid_parameters",
        "invalid_document",
        "invalid_public_key",
        "invalid_algorithm",
    ] {
        assert!(logs.contains(event), "Missing safe warning event: {event}");
    }
    assert!(logs.contains("jacs_sign_document"));
    assert!(logs.contains("unknown"));
}

#[test]
fn default_profile_ignores_ambient_signing_grants_without_changing_vault() {
    let fixture = Fixture::new();
    let path = fixture.directory.path().join("agent.json");
    let before = std::fs::read(&path).unwrap();
    let before_count = std::fs::read_dir(fixture.directory.path()).unwrap().count();
    let mut session = Session::start(fixture.directory.path(), false, true);
    result(&session.request(modern(1, "server/discover", json!({}))));
    let listed = session.request(modern(2, "tools/list", json!({})));
    assert_eq!(listed_names(&listed), ["jacs_verify_document"]);
    invalid_params(&session.request(call(
        3,
        "jacs_sign_document",
        json!({"document":PRIVATE_MARKER}),
    )));
    let verified = payload(&session.request(call(
        4,
        "jacs_verify_document",
        fixture.verify_args(&fixture.signed),
    )));
    assert_eq!(verified["valid"], true);
    session.shutdown();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        std::fs::read_dir(fixture.directory.path()).unwrap().count(),
        before_count
    );
    let logs = String::from_utf8(session.stderr.lock().unwrap().clone()).unwrap();
    assert!(!logs.contains("synthetic-unusable-ambient-password"));
    assert!(!logs.contains("password:"));
    assert!(!logs.contains(PRIVATE_MARKER));
}
