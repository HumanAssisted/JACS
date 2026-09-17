#[cfg(unix)]
use jacs_core::{AgentMaterial, UnlockSecret};
use jacs_core::{CoreAgent, SigningAlgorithm};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const OLD: &str = "test-only-source-passphrase-5mK7w";
const NEW: &str = "test-only-destination-passphrase-4pN8a";

fn private_directory() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

fn run(args: &[&str], old: Option<&str>, new: Option<&str>, stdin: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_jacs"));
    command
        .args(args)
        .env_remove("JACS_PRIVATE_KEY_PASSWORD")
        .env_remove("JACS_NEW_PRIVATE_KEY_PASSWORD")
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(secret) = old {
        command.env("JACS_PRIVATE_KEY_PASSWORD", secret);
    }
    if let Some(secret) = new {
        command.env("JACS_NEW_PRIVATE_KEY_PASSWORD", secret);
    }
    let mut child = command.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_secret(&output);
    serde_json::from_slice(&output.stdout).expect("stdout must contain exactly one JSON value")
}

fn assert_no_secret(output: &Output) {
    for stream in [&output.stdout, &output.stderr] {
        let stream = String::from_utf8_lossy(stream);
        assert!(!stream.contains(OLD));
        assert!(!stream.contains(NEW));
        assert!(!stream.contains("encrypted_private_key"));
    }
}

#[cfg(unix)]
fn material(path: &Path) -> AgentMaterial {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[cfg(unix)]
fn create(path: &Path, algorithm: Option<&str>) -> Value {
    let mut args = vec!["create", "--output", text(path)];
    if let Some(algorithm) = algorithm {
        args.extend(["--algorithm", algorithm]);
    }
    success(run(&args, Some(OLD), None, None))
}

#[test]
#[cfg(unix)]
fn pq_default_sign_verify_public_identity_and_tamper_rejection() {
    let temp = private_directory();
    let path = temp.path().join("agent.json");
    let public = create(&path, None);
    assert_eq!(public["algorithm"], "pq2025");
    assert_eq!(material(&path).algorithm, SigningAlgorithm::Pq2025);
    let public_path = temp.path().join("public.json");
    fs::write(&public_path, public.to_string()).unwrap();
    let signed = success(run(
        &["sign", "--agent", text(&path), "--input", "-"],
        Some(OLD),
        None,
        Some(r#"{"hello":"portable"}"#),
    ));
    let signed_text = signed.to_string();
    let verified = success(run(
        &[
            "verify",
            "--public-identity",
            text(&public_path),
            "--input",
            "-",
        ],
        None,
        None,
        Some(&signed_text),
    ));
    assert_eq!(verified["valid"], true);
    let verified = success(run(
        &["verify", "--agent", text(&path), "--input", "-"],
        None,
        None,
        Some(&signed_text),
    ));
    assert_eq!(verified["valid"], true);
    let mut tampered = signed;
    tampered["content"]["hello"] = json!("changed");
    let output = run(
        &["verify", "--agent", text(&path), "--input", "-"],
        None,
        None,
        Some(&tampered.to_string()),
    );
    assert!(!output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["valid"],
        false
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("WARN"));

    let mut other_id = public;
    other_id["agent_id"] = json!("not-the-trusted-agent");
    fs::write(&public_path, other_id.to_string()).unwrap();
    assert!(
        !run(
            &[
                "verify",
                "--public-identity",
                text(&public_path),
                "--input",
                "-"
            ],
            None,
            None,
            Some(&signed_text)
        )
        .status
        .success()
    );
}

#[test]
#[cfg(unix)]
fn reencrypt_export_import_preserve_identity_and_replace_password() {
    let temp = private_directory();
    let source = temp.path().join("agent.json");
    create(&source, None);
    let original = material(&source);
    let mut previous = source;
    let mut password = OLD;
    for (command, input_flag, next_password) in [
        ("reencrypt", "--agent", NEW),
        ("export", "--agent", OLD),
        ("import", "--input", NEW),
    ] {
        let next = temp.path().join(format!("{command}.json"));
        success(run(
            &[
                command,
                input_flag,
                text(&previous),
                "--output",
                text(&next),
            ],
            Some(password),
            Some(next_password),
            None,
        ));
        let imported = material(&next);
        assert_eq!(imported.agent, original.agent);
        assert_eq!(imported.public_key, original.public_key);
        assert_ne!(
            imported.encrypted_private_key,
            material(&previous).encrypted_private_key
        );
        assert!(
            CoreAgent::from_encrypted_material(
                imported.clone(),
                UnlockSecret::Password(next_password)
            )
            .is_ok()
        );
        assert!(
            CoreAgent::from_encrypted_material(imported, UnlockSecret::Password(password)).is_err()
        );
        previous = next;
        password = next_password;
    }
}

#[test]
#[cfg(unix)]
fn rotation_is_pq_authorized_by_old_key_and_refuses_downgrade() {
    let temp = private_directory();
    let source = temp.path().join("agent.json");
    let destination = temp.path().join("rotated.json");
    create(&source, Some("ed25519"));
    let old = material(&source);
    let old_agent =
        CoreAgent::from_encrypted_material(old.clone(), UnlockSecret::Password(OLD)).unwrap();
    success(run(
        &[
            "rotate",
            "--agent",
            text(&source),
            "--output",
            text(&destination),
        ],
        Some(OLD),
        Some(NEW),
        None,
    ));
    let rotated = material(&destination);
    assert_eq!(rotated.algorithm, SigningAlgorithm::Pq2025);
    assert_eq!(old.agent["jacsId"], rotated.agent["jacsId"]);
    assert_ne!(old.agent["jacsVersion"], rotated.agent["jacsVersion"]);
    assert_ne!(old.public_key, rotated.public_key);
    old_agent
        .verify_key_rotation(&rotated.agent, &rotated.public_key, rotated.algorithm)
        .unwrap();
    let signed = success(run(
        &["sign", "--agent", text(&destination), "--input", "-"],
        Some(NEW),
        None,
        Some(r#"{"rotated":true}"#),
    ));
    assert!(
        CoreAgent::verify_with_key(&signed, &rotated.public_key, rotated.algorithm)
            .unwrap()
            .valid
    );
    let denied = temp.path().join("downgraded.json");
    let output = run(
        &[
            "rotate",
            "--agent",
            text(&destination),
            "--output",
            text(&denied),
            "--algorithm",
            "ed25519",
        ],
        Some(NEW),
        Some(OLD),
        None,
    );
    assert!(!output.status.success());
    assert!(!denied.exists());
    assert_no_secret(&output);
}

#[test]
#[cfg(unix)]
fn wrong_password_duplicate_json_and_overwrite_never_emit_keys() {
    let temp = private_directory();
    let source = temp.path().join("agent.json");
    let destination = temp.path().join("must-not-exist.json");
    create(&source, Some("es256"));
    let original = fs::read(&source).unwrap();
    for args in [
        vec![
            "sign",
            "--agent",
            text(&source),
            "--input",
            "-",
            "--output",
            text(&destination),
        ],
        vec![
            "reencrypt",
            "--agent",
            text(&source),
            "--output",
            text(&destination),
        ],
    ] {
        let output = run(&args, Some("wrong-secret"), Some(NEW), Some("{}"));
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!destination.exists());
        assert_no_secret(&output);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("wrong-secret"));
    }
    let output = run(
        &["sign", "--agent", text(&source), "--input", "-"],
        Some(OLD),
        None,
        Some(r#"{"x":1,"x":2}"#),
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let output = run(
        &["create", "--output", text(&source)],
        Some(NEW),
        None,
        None,
    );
    assert!(!output.status.success());
    assert_eq!(original, fs::read(&source).unwrap());
}

#[test]
#[cfg(unix)]
fn private_permissions_and_plaintext_import_rejection() {
    use std::os::unix::fs::PermissionsExt;
    let temp = private_directory();
    let path = temp.path().join("agent.json");
    create(&path, None);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut plaintext = serde_json::to_value(material(&path)).unwrap();
    plaintext["encrypted_private_key"] = json!("cGxhaW50ZXh0");
    fs::write(&path, plaintext.to_string()).unwrap();
    let output_path = temp.path().join("import.json");
    let output = run(
        &[
            "import",
            "--input",
            text(&path),
            "--output",
            text(&output_path),
        ],
        Some(OLD),
        Some(NEW),
        None,
    );
    assert!(!output.status.success());
    assert!(!output_path.exists());
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let output = run(
        &["create", "--output", text(&output_path)],
        Some(OLD),
        None,
        None,
    );
    assert!(!output.status.success());
    assert!(!output_path.exists());
}

#[test]
fn mcp_profile_requires_explicit_local_authority() {
    for args in [
        vec!["mcp", "--profile", "local-sign"],
        vec!["mcp", "--agent", "not-loaded.json"],
    ] {
        let output = run(&args, Some(OLD), Some(NEW), None);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_no_secret(&output);
    }
}

#[test]
fn public_verification_is_available_without_private_storage() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let temp = private_directory();
    let mut agent = CoreAgent::ephemeral(SigningAlgorithm::Pq2025).unwrap();
    let public = json!({"agent_id":agent.export_agent()["jacsId"], "public_key":STANDARD.encode(agent.public_key()), "algorithm":"pq2025"});
    let public_path = temp.path().join("public.json");
    fs::write(&public_path, public.to_string()).unwrap();
    let signed = agent.sign_message(&json!({"portable":true})).unwrap();
    let output = success(run(
        &[
            "verify",
            "--public-identity",
            text(&public_path),
            "--input",
            "-",
        ],
        None,
        None,
        Some(&signed.to_string()),
    ));
    assert_eq!(output["valid"], true);
}
