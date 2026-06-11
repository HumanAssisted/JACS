use assert_cmd::Command;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const TEST_PASSWORD: &str = "TestAgreementV2!2026";
const AGREEMENT_V2_SCENARIO: &str =
    include_str!("../../binding-core/tests/fixtures/agreement_v2_scenarios.json");

fn cmd() -> Command {
    let mut c = Command::cargo_bin("jacs").expect("jacs binary should exist");
    c.env("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    c
}

fn bootstrap_agent(dir: &TempDir) {
    cmd()
        .current_dir(dir.path())
        .args([
            "quickstart",
            "--algorithm",
            "ed25519",
            "--name",
            "agreement-v2-cli-test",
            "--domain",
            "localhost",
        ])
        .assert()
        .success();
}

fn configured_agent_id(dir: &TempDir) -> String {
    let config: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("jacs.config.json")).unwrap(),
    )
    .expect("config json");
    config["jacs_agent_id_and_version"]
        .as_str()
        .expect("configured agent id")
        .split(':')
        .next()
        .expect("agent id")
        .to_string()
}

fn write_json(dir: &TempDir, name: &str, value: &Value) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, serde_json::to_vec_pretty(value).expect("json bytes")).expect("write");
    path
}

fn output_json(dir: &TempDir, args: &[&str]) -> Value {
    let output = cmd()
        .current_dir(dir.path())
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap_or_else(|err| {
        panic!(
            "stdout was not JSON: {}\n{}",
            err,
            String::from_utf8_lossy(&output)
        )
    })
}

fn output_json_with_paths(dir: &TempDir, args: &[&str], paths: &[&Path]) -> Value {
    let mut command = cmd();
    command.current_dir(dir.path()).args(args);
    for path in paths {
        command.arg(path);
    }
    let output = command.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).unwrap_or_else(|err| {
        panic!(
            "stdout was not JSON: {}\n{}",
            err,
            String::from_utf8_lossy(&output)
        )
    })
}

fn output_json_owned(dir: &TempDir, args: &[String]) -> Value {
    let output = cmd()
        .current_dir(dir.path())
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap_or_else(|err| {
        panic!(
            "stdout was not JSON: {}\n{}",
            err,
            String::from_utf8_lossy(&output)
        )
    })
}

fn fixture() -> Value {
    serde_json::from_str(AGREEMENT_V2_SCENARIO).expect("agreement v2 scenario fixture")
}

fn base_input(agent_id: &str) -> Value {
    let scenario = fixture();
    let mut input = scenario["base_input"].clone();
    input["parties"] = json!([
        {"agentId": agent_id, "agentType": "ai", "role": "signer"}
    ]);
    input["controllers"] = json!([agent_id]);
    input
}

fn transcript_ref(name: &str) -> Value {
    fixture()["transcript_refs"][name].clone()
}

fn conflict_terms(name: &str) -> String {
    fixture()["terms_conflict"][name]
        .as_str()
        .expect("terms conflict value")
        .to_string()
}

#[test]
fn agreement_v2_cli_executes_full_public_workflow() {
    let dir = TempDir::new().expect("tmpdir");
    bootstrap_agent(&dir);
    let agent_id = configured_agent_id(&dir);

    let input_path = write_json(&dir, "agreement-input.json", &base_input(&agent_id));
    let created =
        output_json_with_paths(&dir, &["agreement-v2", "create", "--input"], &[&input_path]);
    assert_eq!(created["jacsType"], json!("agreement"));

    let created_path = write_json(&dir, "created.json", &created);
    let signed = output_json_with_paths(
        &dir,
        &["agreement-v2", "sign", "--agreement"],
        &[&created_path],
    );
    assert_eq!(signed["agreementSignatures"][0]["role"], json!("signer"));

    let signed_path = write_json(&dir, "signed.json", &signed);
    let report = output_json_with_paths(
        &dir,
        &["agreement-v2", "verify", "--agreement"],
        &[&signed_path],
    );
    assert_eq!(report["valid"], json!(true));
    assert_eq!(report["expectedStatus"], json!("final"));

    let left_mutation = write_json(
        &dir,
        "left-transcript.json",
        &json!({"type": "appendTranscript", "entry": transcript_ref("left")}),
    );
    let right_mutation = write_json(
        &dir,
        "right-transcript.json",
        &json!({"type": "appendTranscript", "entry": transcript_ref("right")}),
    );
    let left = output_json_owned(
        &dir,
        &[
            "agreement-v2".to_string(),
            "apply".to_string(),
            "--agreement".to_string(),
            created_path.to_string_lossy().into_owned(),
            "--mutation".to_string(),
            left_mutation.to_string_lossy().into_owned(),
        ],
    );
    let right = output_json_owned(
        &dir,
        &[
            "agreement-v2".to_string(),
            "apply".to_string(),
            "--agreement".to_string(),
            created_path.to_string_lossy().into_owned(),
            "--mutation".to_string(),
            right_mutation.to_string_lossy().into_owned(),
        ],
    );
    let left_path = write_json(&dir, "left.json", &left);
    let right_path = write_json(&dir, "right.json", &right);

    let analysis = output_json(
        &dir,
        &[
            "agreement-v2",
            "detect-conflict",
            "--base",
            created_path.to_str().unwrap(),
            "--left",
            left_path.to_str().unwrap(),
            "--right",
            right_path.to_str().unwrap(),
        ],
    );
    assert_eq!(analysis["autoMergeable"], json!(true));

    let merged = output_json(
        &dir,
        &[
            "agreement-v2",
            "merge-transcript",
            "--base",
            created_path.to_str().unwrap(),
            "--left",
            left_path.to_str().unwrap(),
            "--right",
            right_path.to_str().unwrap(),
        ],
    );
    assert_eq!(merged["transcript"].as_array().unwrap().len(), 2);

    let left_terms_mutation = write_json(
        &dir,
        "left-terms.json",
        &json!({"type": "updateTerms", "terms": conflict_terms("left")}),
    );
    let right_terms_mutation = write_json(
        &dir,
        "right-terms.json",
        &json!({"type": "updateTerms", "terms": conflict_terms("right")}),
    );
    let left_terms = output_json_owned(
        &dir,
        &[
            "agreement-v2".to_string(),
            "apply".to_string(),
            "--agreement".to_string(),
            created_path.to_string_lossy().into_owned(),
            "--mutation".to_string(),
            left_terms_mutation.to_string_lossy().into_owned(),
        ],
    );
    let right_terms = output_json_owned(
        &dir,
        &[
            "agreement-v2".to_string(),
            "apply".to_string(),
            "--agreement".to_string(),
            created_path.to_string_lossy().into_owned(),
            "--mutation".to_string(),
            right_terms_mutation.to_string_lossy().into_owned(),
        ],
    );
    let left_terms_path = write_json(&dir, "left-terms-doc.json", &left_terms);
    let right_terms_path = write_json(&dir, "right-terms-doc.json", &right_terms);
    let resolution = write_json(
        &dir,
        "resolution.json",
        &json!({"type": "updateTerms", "terms": conflict_terms("resolved")}),
    );
    let resolved = output_json(
        &dir,
        &[
            "agreement-v2",
            "resolve-conflict",
            "--base",
            created_path.to_str().unwrap(),
            "--previous",
            left_terms_path.to_str().unwrap(),
            "--side-branch",
            right_terms_path.to_str().unwrap(),
            "--mutation",
            resolution.to_str().unwrap(),
        ],
    );
    assert_eq!(resolved["terms"], json!(conflict_terms("resolved")));
    let resolution_link = &resolved["links"][0];
    assert_eq!(
        resolution_link["jacsId"], right_terms["jacsId"],
        "resolution link must reference the side branch's jacsId"
    );
    assert_eq!(
        resolution_link["jacsVersion"], right_terms["jacsVersion"],
        "resolution link must reference the side branch's jacsVersion"
    );
}

#[test]
fn agreement_v2_cli_verify_exits_nonzero_on_tampered() {
    let dir = TempDir::new().expect("tmpdir");
    bootstrap_agent(&dir);
    let agent_id = configured_agent_id(&dir);

    let input_path = write_json(&dir, "agreement-input.json", &base_input(&agent_id));
    let created =
        output_json_with_paths(&dir, &["agreement-v2", "create", "--input"], &[&input_path]);
    let created_path = write_json(&dir, "created.json", &created);
    let signed = output_json_with_paths(
        &dir,
        &["agreement-v2", "sign", "--agreement"],
        &[&created_path],
    );
    let signed_path = write_json(&dir, "signed.json", &signed);

    // VALID agreement -> exit 0.
    cmd()
        .current_dir(dir.path())
        .args(["agreement-v2", "verify", "--agreement"])
        .arg(&signed_path)
        .assert()
        .success();

    // TAMPERED agreement (breaks the JACS content hash) -> non-zero exit.
    let mut tampered = signed.clone();
    assert!(
        tampered.get("terms").is_some(),
        "signed agreement must include top-level terms: {}",
        tampered
    );
    tampered["terms"] = json!("tampered terms that break the hash");
    let tampered_path = write_json(&dir, "tampered.json", &tampered);
    cmd()
        .current_dir(dir.path())
        .args(["agreement-v2", "verify", "--agreement"])
        .arg(&tampered_path)
        .assert()
        .failure();
}

/// The fail-open regression: an agreement signed by ANOTHER agent whose key the
/// verifier cannot resolve verifies to `Ok(report { valid: false })` (not Err).
/// Before the fix the CLI printed the invalid report and exited 0; the handler
/// must now inspect `report.valid` and exit non-zero so `verify ... && next`
/// idioms cannot proceed on an unverifiable agreement.
#[test]
fn agreement_v2_cli_verify_exits_nonzero_on_unverifiable_signer() {
    // Signer agent A produces a fully signed agreement.
    let signer_dir = TempDir::new().expect("signer tmpdir");
    bootstrap_agent(&signer_dir);
    let signer_id = configured_agent_id(&signer_dir);

    let input_path = write_json(&signer_dir, "agreement-input.json", &base_input(&signer_id));
    let created = output_json_with_paths(
        &signer_dir,
        &["agreement-v2", "create", "--input"],
        &[&input_path],
    );
    let created_path = write_json(&signer_dir, "created.json", &created);
    let signed = output_json_with_paths(
        &signer_dir,
        &["agreement-v2", "sign", "--agreement"],
        &[&created_path],
    );
    // Sanity: signer's own verification is valid (Ok report, valid=true, exit 0).
    let signed_path = write_json(&signer_dir, "signed.json", &signed);
    cmd()
        .current_dir(signer_dir.path())
        .args(["agreement-v2", "verify", "--agreement"])
        .arg(&signed_path)
        .assert()
        .success();

    // Fresh verifier agent B cannot resolve A's key -> Ok(report{ valid:false }).
    let verifier_dir = TempDir::new().expect("verifier tmpdir");
    bootstrap_agent(&verifier_dir);
    let verifier_signed_path = write_json(&verifier_dir, "signed.json", &signed);
    cmd()
        .current_dir(verifier_dir.path())
        // Keep remote key fetch disabled (the default) so the signer key is
        // unresolvable and the report is valid:false rather than Err.
        .env_remove("JACS_ALLOW_REMOTE_KEY_FETCH")
        .env_remove("JACS_ALLOW_NETWORK")
        .args(["agreement-v2", "verify", "--agreement"])
        .arg(&verifier_signed_path)
        .assert()
        .failure();
}

/// Discoverability + back-compat: bare `agreement-v2` must print help and exit
/// non-zero (no silent stdout nudge), and `--side` must still resolve as a
/// hidden alias for the renamed `--side-branch` flag.
#[test]
fn agreement_v2_bare_prints_help_and_side_alias_still_works() {
    // Bare `jacs agreement-v2` -> non-zero exit, help on stderr.
    let assert = cmd().args(["agreement-v2"]).assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("Usage") || stderr.contains("SUBCOMMAND") || stderr.contains("subcommand"),
        "bare agreement-v2 should print help/usage to stderr, got: {stderr}"
    );

    // `--help` for resolve-conflict should advertise the renamed flag.
    let help = cmd()
        .args(["agreement-v2", "resolve-conflict", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8_lossy(&help).to_string();
    assert!(
        help.contains("--side-branch"),
        "resolve-conflict --help should advertise --side-branch, got: {help}"
    );

    // `--side` alias drives the same resolve-conflict workflow as `--side-branch`.
    let dir = TempDir::new().expect("tmpdir");
    bootstrap_agent(&dir);
    let agent_id = configured_agent_id(&dir);

    let input_path = write_json(&dir, "agreement-input.json", &base_input(&agent_id));
    let created =
        output_json_with_paths(&dir, &["agreement-v2", "create", "--input"], &[&input_path]);
    let created_path = write_json(&dir, "created.json", &created);

    let left_terms_mutation = write_json(
        &dir,
        "left-terms.json",
        &json!({"type": "updateTerms", "terms": conflict_terms("left")}),
    );
    let right_terms_mutation = write_json(
        &dir,
        "right-terms.json",
        &json!({"type": "updateTerms", "terms": conflict_terms("right")}),
    );
    let left_terms = output_json_owned(
        &dir,
        &[
            "agreement-v2".to_string(),
            "apply".to_string(),
            "--agreement".to_string(),
            created_path.to_string_lossy().into_owned(),
            "--mutation".to_string(),
            left_terms_mutation.to_string_lossy().into_owned(),
        ],
    );
    let right_terms = output_json_owned(
        &dir,
        &[
            "agreement-v2".to_string(),
            "apply".to_string(),
            "--agreement".to_string(),
            created_path.to_string_lossy().into_owned(),
            "--mutation".to_string(),
            right_terms_mutation.to_string_lossy().into_owned(),
        ],
    );
    let left_terms_path = write_json(&dir, "left-terms-doc.json", &left_terms);
    let right_terms_path = write_json(&dir, "right-terms-doc.json", &right_terms);
    let resolution = write_json(
        &dir,
        "resolution.json",
        &json!({"type": "updateTerms", "terms": conflict_terms("resolved")}),
    );

    // Use the LEGACY `--side` alias here on purpose.
    let resolved = output_json(
        &dir,
        &[
            "agreement-v2",
            "resolve-conflict",
            "--base",
            created_path.to_str().unwrap(),
            "--previous",
            left_terms_path.to_str().unwrap(),
            "--side",
            right_terms_path.to_str().unwrap(),
            "--mutation",
            resolution.to_str().unwrap(),
        ],
    );
    assert_eq!(resolved["terms"], json!(conflict_terms("resolved")));
    assert_eq!(
        resolved["links"][0]["jacsId"], right_terms["jacsId"],
        "--side alias must drive resolve-conflict identically to --side-branch"
    );
}

#[test]
fn agreement_v2_cli_create_reads_input_from_stdin() {
    let dir = TempDir::new().expect("tmpdir");
    bootstrap_agent(&dir);
    let agent_id = configured_agent_id(&dir);

    let input = base_input(&agent_id);
    let input_string = serde_json::to_string(&input).expect("input json");
    let output = cmd()
        .current_dir(dir.path())
        .args(["agreement-v2", "create", "--input", "-"])
        .write_stdin(input_string)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let created: Value = serde_json::from_slice(&output).expect("created agreement json");

    assert_eq!(created["jacsType"], json!("agreement"));
    if let Some(agent_id_value) = created.pointer("/parties/0/agentId") {
        assert_eq!(agent_id_value, &json!(agent_id));
    }
}

#[test]
fn agreement_v2_cli_notary_role_signs_and_verifies() {
    let signer_dir = TempDir::new().expect("tmpdir");
    bootstrap_agent(&signer_dir);
    let signer_id = configured_agent_id(&signer_dir);

    let notary_dir = TempDir::new().expect("tmpdir");
    bootstrap_agent(&notary_dir);
    let notary_id = configured_agent_id(&notary_dir);

    let mut input = base_input(&signer_id);
    input["parties"] = json!([
        {"agentId": signer_id, "agentType": "ai", "role": "signer"},
        {"agentId": notary_id, "agentType": "ai", "role": "notary"}
    ]);
    input["signaturePolicy"]["notaryRequired"] = json!(1);
    input["controllers"] = json!([signer_id, notary_id]);

    let input_path = write_json(&signer_dir, "agreement-input.json", &input);
    let created = output_json_with_paths(
        &signer_dir,
        &["agreement-v2", "create", "--input"],
        &[&input_path],
    );
    assert_eq!(created["jacsType"], json!("agreement"));

    let created_path = write_json(&notary_dir, "created.json", &created);
    let notarized = output_json_with_paths(
        &notary_dir,
        &["agreement-v2", "sign", "--role", "notary", "--agreement"],
        &[&created_path],
    );
    assert_eq!(notarized["agreementSignatures"][0]["role"], json!("notary"));

    let signer_public_keys = signer_dir.path().join("jacs_data/public_keys");
    let notary_public_keys = notary_dir.path().join("jacs_data/public_keys");
    for entry in std::fs::read_dir(&notary_public_keys).expect("notary public keys") {
        let entry = entry.expect("notary public key entry");
        std::fs::copy(entry.path(), signer_public_keys.join(entry.file_name()))
            .expect("copy notary public key");
    }

    let notarized_path = write_json(&signer_dir, "notarized.json", &notarized);
    let signed = output_json_with_paths(
        &signer_dir,
        &["agreement-v2", "sign", "--agreement"],
        &[&notarized_path],
    );
    assert_eq!(signed["agreementSignatures"][0]["role"], json!("notary"));

    let signed_path = write_json(&signer_dir, "signed.json", &signed);
    let report = output_json_with_paths(
        &signer_dir,
        &["agreement-v2", "verify", "--agreement"],
        &[&signed_path],
    );
    assert_eq!(report["valid"], json!(true));
}
