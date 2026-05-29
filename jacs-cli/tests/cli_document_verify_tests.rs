use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "TestDocumentVerify!2026";

fn cmd() -> Command {
    let mut c = Command::cargo_bin("jacs").expect("jacs binary should exist");
    c.env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    c
}

fn sign_document(dir: &TempDir) -> Value {
    let input_path = dir.path().join("input.json");
    std::fs::write(
        &input_path,
        r#"{"message":"document verify forgery check"}"#,
    )
    .expect("write input");

    let output = cmd()
        .current_dir(dir.path())
        .args([
            "quickstart",
            "--algorithm",
            "ed25519",
            "--name",
            "document-verify-test",
            "--domain",
            "localhost",
            "--sign",
            "-f",
        ])
        .arg(&input_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    serde_json::from_slice(&output).unwrap_or_else(|err| {
        panic!(
            "signed document stdout was not JSON: {}\n{}",
            err,
            String::from_utf8_lossy(&output)
        )
    })
}

fn replace_signature_with_forgery(document: &mut Value) {
    let signature = document["jacsSignature"]["signature"]
        .as_str()
        .expect("signature string");
    let mut forged_signature = signature.to_string();
    forged_signature.replace_range(0..1, if signature.starts_with('A') { "B" } else { "A" });
    document["jacsSignature"]["signature"] = Value::String(forged_signature);
}

fn recompute_document_hash(document: &mut Value) {
    document
        .as_object_mut()
        .expect("signed document object")
        .remove("jacsSha256");
    let canonical = jacs::protocol::canonicalize_json(document);
    let digest = jacs::crypt::hash::hash_string(&canonical);
    document
        .as_object_mut()
        .expect("signed document object")
        .insert("jacsSha256".to_string(), Value::String(digest));
}

#[test]
fn document_verify_rejects_forged_signature_even_when_hash_matches() {
    let dir = TempDir::new().expect("tmpdir");
    let signed = sign_document(&dir);
    let signed_path = dir.path().join("signed.json");
    std::fs::write(
        &signed_path,
        serde_json::to_vec_pretty(&signed).expect("signed json bytes"),
    )
    .expect("write signed document");

    cmd()
        .current_dir(dir.path())
        .args(["document", "verify", "-f"])
        .arg(&signed_path)
        .assert()
        .success();

    let mut forged = signed;
    replace_signature_with_forgery(&mut forged);
    recompute_document_hash(&mut forged);

    let forged_path = dir.path().join("forged.json");
    std::fs::write(
        &forged_path,
        serde_json::to_vec_pretty(&forged).expect("forged json bytes"),
    )
    .expect("write forged document");

    cmd()
        .current_dir(dir.path())
        .args(["document", "verify", "-f"])
        .arg(&forged_path)
        .assert()
        .failure();
}
