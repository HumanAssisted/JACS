#![cfg(feature = "mcp")]

use jacs_binding_core::AgentWrapper;
use jacs_mcp::{JacsMcpServer, Profile};
use rmcp::handler::server::wrapper::Parameters;
use serde_json::{Value, json};

mod support;

struct Workspace(std::path::PathBuf);
impl Drop for Workspace {
    fn drop(&mut self) {
        support::cleanup_workspace(&self.0);
    }
}

#[tokio::test]
#[serial_test::serial(mcp_local_signing_env)]
async fn explicit_content_grant_reuses_loaded_signer_and_captures_file_policy() {
    let (config, base) = support::prepare_temp_workspace();
    let _workspace = Workspace(base.clone());
    let _password = support::ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", support::TEST_PASSWORD);
    let _root = support::ScopedEnvVar::set("JACS_MCP_BASE_DIR", &base);
    let _overwrite = support::ScopedEnvVar::set("JACS_MCP_OVERWRITE_OK", "false");
    let _keys = support::ScopedEnvVar::set("JACS_MCP_ALLOW_KEY_DIR", "false");
    assert_eq!(JacsMcpServer::verification_only().active_tools().len(), 1);
    let server = JacsMcpServer::local_signing_from_config(&config).unwrap();
    let names: Vec<_> = server
        .active_tools()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(
        names.len(),
        if cfg!(feature = "agreement-tools") {
            14
        } else {
            7
        }
    );
    for name in [
        "jacs_sign_text",
        "jacs_verify_text",
        "jacs_sign_image",
        "jacs_verify_image",
        "jacs_extract_media_signature",
    ] {
        assert!(names.iter().any(|n| n == name), "{name}");
    }
    for name in [
        "jacs_create_agent",
        "jacs_rotate_keys",
        "jacs_trust_agent",
        "jacs_attest_create",
        "jacs_wrap_a2a_artifact",
    ] {
        assert!(!names.iter().any(|n| n == name), "{name}");
    }

    // Construction, not ambient configuration on each call, selects authority.
    let other = tempfile::TempDir::new().unwrap();
    let _changed_root = support::ScopedEnvVar::set("JACS_MCP_BASE_DIR", other.path());
    let _changed_password =
        support::ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", "wrong-after-startup");
    let _changed_config = support::ScopedEnvVar::set("JACS_CONFIG", base.join("missing.json"));
    let _changed_overwrite = support::ScopedEnvVar::set("JACS_MCP_OVERWRITE_OK", "true");
    let _changed_keys = support::ScopedEnvVar::set("JACS_MCP_ALLOW_KEY_DIR", "true");
    let original = b"# Stable local signing\n";
    std::fs::write(base.join("note.md"), original).unwrap();
    let signed: Value = serde_json::from_str(
        &server
            .jacs_sign_text(Parameters(
                serde_json::from_value(json!({"file_path":"note.md"})).unwrap(),
            ))
            .await,
    )
    .unwrap();
    assert_eq!(signed["success"], true, "{signed}");
    assert_eq!(signed["signers_added"], 1);
    assert_eq!(std::fs::read(base.join("note.md.bak")).unwrap(), original);
    assert!(!other.path().join("note.md").exists());
    let verified: Value = serde_json::from_str(
        &server
            .jacs_verify_text(Parameters(
                serde_json::from_value(json!({"file_path":"note.md","strict":true})).unwrap(),
            ))
            .await,
    )
    .unwrap();
    assert_eq!(verified["success"], true, "{verified}");
    assert_eq!(verified["signatures"][0]["status"], "valid");
    assert_eq!(verified["signatures"][0]["signer_id"], signed["signer_id"]);
    let unchanged: Value = serde_json::from_str(
        &server
            .jacs_sign_text(Parameters(
                serde_json::from_value(json!({"file_path":"note.md"})).unwrap(),
            ))
            .await,
    )
    .unwrap();
    assert_eq!(unchanged["success"], true, "{unchanged}");
    assert_eq!(unchanged["signers_added"], 0);
    assert_eq!(std::fs::read(base.join("note.md.bak")).unwrap(), original);
    let denied: Value = serde_json::from_str(
        &server
            .jacs_verify_text(Parameters(
                serde_json::from_value(json!({"file_path":"note.md","key_dir":"public"})).unwrap(),
            ))
            .await,
    )
    .unwrap();
    assert_eq!(denied["success"], false, "{denied}");
    assert!(denied["error"].as_str().unwrap().contains("disabled"));

    let image = image::RgbImage::from_pixel(2, 2, image::Rgb([64, 128, 192]));
    image.save(base.join("input.png")).unwrap();
    std::fs::write(base.join("occupied.png"), b"do not replace").unwrap();
    let blocked: Value = serde_json::from_str(&server.jacs_sign_image(Parameters(
        serde_json::from_value(json!({"input_path":"input.png","output_path":"occupied.png","refuse_overwrite":false})).unwrap()
    )).await).unwrap();
    assert_eq!(blocked["success"], false, "{blocked}");
    assert_eq!(
        std::fs::read(base.join("occupied.png")).unwrap(),
        b"do not replace"
    );
    let signed_image: Value = serde_json::from_str(
        &server
            .jacs_sign_image(Parameters(
                serde_json::from_value(
                    json!({"input_path":"input.png","output_path":"signed.png"}),
                )
                .unwrap(),
            ))
            .await,
    )
    .unwrap();
    assert_eq!(signed_image["success"], true, "{signed_image}");
    assert_eq!(signed_image["signer_id"], signed["signer_id"]);
    let verified_image: Value = serde_json::from_str(
        &server
            .jacs_verify_image(Parameters(
                serde_json::from_value(json!({"file_path":"signed.png","strict":true})).unwrap(),
            ))
            .await,
    )
    .unwrap();
    assert_eq!(verified_image["status"], "valid", "{verified_image}");
    let extracted: Value = serde_json::from_str(
        &server
            .jacs_extract_media_signature(Parameters(
                serde_json::from_value(json!({"file_path":"signed.png"})).unwrap(),
            ))
            .await,
    )
    .unwrap();
    assert_eq!(extracted["present"], true, "{extracted}");
}

#[tokio::test]
#[serial_test::serial(mcp_local_signing_env)]
async fn content_grant_excludes_identity_storage_and_backup_targets() {
    let (config, base) = support::prepare_temp_workspace();
    let _workspace = Workspace(base.clone());
    let _password = support::ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", support::TEST_PASSWORD);
    let _root = support::ScopedEnvVar::set("JACS_MCP_BASE_DIR", &base);
    let _trust = support::ScopedEnvVar::set("JACS_TRUST_STORE_DIR", base.join("trusted"));
    let server = JacsMcpServer::local_signing_from_config(&config).unwrap();
    for invalid_root in [
        base.join("jacs_keys"),
        base.join("jacs_data"),
        config.clone(),
        base.join("missing-root"),
    ] {
        let _invalid = support::ScopedEnvVar::set("JACS_MCP_BASE_DIR", invalid_root);
        assert!(JacsMcpServer::local_signing_from_config(&config).is_err());
    }
    let config_before = std::fs::read(&config).unwrap();
    for path in [
        "jacs.config.json",
        "jacs_keys/private.pem",
        "jacs_data/agent.json",
        "documents/payload.json",
        "trusted/identity.json",
        "../outside.md",
        "/tmp/outside.md",
    ] {
        let denied: Value = serde_json::from_str(
            &server
                .jacs_sign_text(Parameters(
                    serde_json::from_value(json!({"file_path":path,"no_backup":true})).unwrap(),
                ))
                .await,
        )
        .unwrap();
        assert_eq!(denied["success"], false, "{path}: {denied}");
        assert!(
            denied["error"]
                .as_str()
                .unwrap()
                .contains("PATH_POLICY_BLOCKED"),
            "{path}: {denied}"
        );
    }
    assert_eq!(std::fs::read(&config).unwrap(), config_before);
    let protected_verify: Value = serde_json::from_str(
        &server
            .jacs_verify_text(Parameters(
                serde_json::from_value(json!({"file_path":"jacs.config.json"})).unwrap(),
            ))
            .await,
    )
    .unwrap();
    assert_eq!(protected_verify["success"], false);
    assert!(
        protected_verify["error"]
            .as_str()
            .unwrap()
            .contains("PATH_POLICY_BLOCKED")
    );
    let protected_image: Value = serde_json::from_str(
        &server
            .jacs_verify_image(Parameters(
                serde_json::from_value(json!({"file_path":"jacs.config.json"})).unwrap(),
            ))
            .await,
    )
    .unwrap();
    assert_eq!(protected_image["success"], false);
    assert!(
        protected_image["error"]
            .as_str()
            .unwrap()
            .contains("PATH_POLICY_BLOCKED")
    );
    let protected_extract: Value = serde_json::from_str(
        &server
            .jacs_extract_media_signature(Parameters(
                serde_json::from_value(json!({"file_path":"jacs.config.json"})).unwrap(),
            ))
            .await,
    )
    .unwrap();
    assert_eq!(protected_extract["success"], false);
    assert!(
        protected_extract["error"]
            .as_str()
            .unwrap()
            .contains("PATH_POLICY_BLOCKED")
    );
    image::RgbImage::from_pixel(2, 2, image::Rgb([1, 2, 3]))
        .save(base.join("input.png"))
        .unwrap();
    let protected_output: Value = serde_json::from_str(
        &server
            .jacs_sign_image(Parameters(
                serde_json::from_value(
                    json!({"input_path":"input.png","output_path":"documents/new.png"}),
                )
                .unwrap(),
            ))
            .await,
    )
    .unwrap();
    assert_eq!(protected_output["success"], false);
    assert!(
        protected_output["error"]
            .as_str()
            .unwrap()
            .contains("PATH_POLICY_BLOCKED")
    );

    // Backup validation happens before the existing signer touches the input.
    std::fs::write(base.join("note.md"), b"original").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&config, base.join("note.md.bak")).unwrap();
        let denied: Value = serde_json::from_str(
            &server
                .jacs_sign_text(Parameters(
                    serde_json::from_value(json!({"file_path":"note.md"})).unwrap(),
                ))
                .await,
        )
        .unwrap();
        assert_eq!(denied["success"], false, "{denied}");
        assert!(
            denied["error"]
                .as_str()
                .unwrap()
                .contains("PATH_POLICY_BLOCKED")
        );
        assert_eq!(std::fs::read(base.join("note.md")).unwrap(), b"original");
        assert_eq!(std::fs::read(&config).unwrap(), config_before);
    }
}

#[tokio::test]
#[serial_test::serial(mcp_local_signing_env)]
async fn captured_overwrite_permission_keeps_image_backup_and_in_place_workflows() {
    let (config, base) = support::prepare_temp_workspace();
    let _workspace = Workspace(base.clone());
    let _password = support::ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", support::TEST_PASSWORD);
    let _root = support::ScopedEnvVar::set("JACS_MCP_BASE_DIR", &base);
    let _overwrite = support::ScopedEnvVar::set("JACS_MCP_OVERWRITE_OK", "true");
    let server = JacsMcpServer::local_signing_from_config(&config).unwrap();
    let _changed = support::ScopedEnvVar::set("JACS_MCP_OVERWRITE_OK", "false");
    image::RgbImage::from_pixel(2, 2, image::Rgb([1, 2, 3]))
        .save(base.join("input.png"))
        .unwrap();
    let original = std::fs::read(base.join("input.png")).unwrap();
    std::fs::write(base.join("output.png"), b"previous output").unwrap();
    for output in ["output.png", "input.png"] {
        let signed: Value = serde_json::from_str(
            &server
                .jacs_sign_image(Parameters(
                    serde_json::from_value(json!({"input_path":"input.png","output_path":output}))
                        .unwrap(),
                ))
                .await,
        )
        .unwrap();
        assert_eq!(signed["success"], true, "{signed}");
        let verified: Value = serde_json::from_str(
            &server
                .jacs_verify_image(Parameters(
                    serde_json::from_value(json!({"file_path":output,"strict":true})).unwrap(),
                ))
                .await,
        )
        .unwrap();
        assert_eq!(verified["status"], "valid", "{verified}");
    }
    assert_eq!(
        std::fs::read(base.join("output.png.bak")).unwrap(),
        b"previous output"
    );
    assert_eq!(std::fs::read(base.join("input.png.bak")).unwrap(), original);
}

#[tokio::test]
async fn a_profile_enum_cannot_authorize_a_direct_signing_handler() {
    let server = JacsMcpServer::with_profile(AgentWrapper::new(), Profile::LocalSign);
    let result = server
        .jacs_sign_document(Parameters(jacs_mcp::tools::SignDocumentParams {
            content: json!({ "hello": "local agent" }).to_string(),
            content_type: None,
        }))
        .await;
    let result: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(result["success"], false);
    assert_eq!(result["error"], "LOCAL_SIGNING_NOT_AUTHORIZED");
    assert_eq!(server.active_tools().len(), 1);
}

#[tokio::test]
#[serial_test::serial(mcp_local_signing_env)]
async fn explicit_config_signs_only_an_ordinary_envelope_and_preserves_storage() {
    let (config, base) = support::prepare_temp_workspace();
    let _workspace = Workspace(base.clone());
    let _password = support::ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", support::TEST_PASSWORD);
    let server =
        JacsMcpServer::local_signing_from_config(&config).expect("authorized local signer");

    // A caller's protocol-looking fields are data, never the signed envelope's authority.
    let supplied = json!({
        "jacsType": "agent", "$schema": "https://invalid.example/control.json",
        "jacsSignature": { "agentID": "not-the-local-signer" }, "hello": "local agent"
    });
    let result = server
        .jacs_sign_document(Parameters(jacs_mcp::tools::SignDocumentParams {
            content: supplied.to_string(),
            content_type: None,
        }))
        .await;
    let result: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(result["success"], true, "{result}");
    let document: Value =
        serde_json::from_str(result["signed_document"].as_str().unwrap()).unwrap();
    assert_eq!(document["jacsType"], "document");
    assert_eq!(document["jacsLevel"], "raw");
    assert_eq!(document["content"], supplied);
    assert_ne!(document["jacsSignature"]["agentID"], "not-the-local-signer");
    let id = document["jacsId"].as_str().unwrap();
    let version = document["jacsVersion"].as_str().unwrap();
    assert!(
        base.join(format!("documents/{id}:{version}.json"))
            .is_file()
    );

    let names: Vec<_> = server
        .active_tools()
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert!(names.iter().any(|name| name == "jacs_sign_document"));
    for forbidden in [
        "jacs_create_agent",
        "jacs_rotate_keys",
        "jacs_reencrypt_key",
        "jacs_trust_agent",
        "jacs_untrust_agent",
        "jacs_sign_text",
        "jacs_sign_image",
        "jacs_sign_agreement",
        "jacs_w3c_sign_request",
    ] {
        assert!(!names.iter().any(|name| name == forbidden), "{forbidden}");
    }
}

#[test]
#[serial_test::serial(mcp_local_signing_env)]
fn missing_unsigned_or_tampered_configuration_cannot_enable_signing() {
    let (config, base) = support::prepare_temp_workspace();
    let _workspace = Workspace(base.clone());
    let _password = support::ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", support::TEST_PASSWORD);
    assert!(JacsMcpServer::local_signing_from_config(base.join("missing.json")).is_err());
    let original = std::fs::read_to_string(&config).unwrap();
    let mut unsigned: Value = serde_json::from_str(&original).unwrap();
    unsigned.as_object_mut().unwrap().remove("jacsSignature");
    let unsigned_path = base.join("unsigned.json");
    std::fs::write(&unsigned_path, serde_json::to_vec(&unsigned).unwrap()).unwrap();
    let _compatibility = support::ScopedEnvVar::set("JACS_ALLOW_UNSIGNED_AGENT_CONFIG", "true");
    assert!(JacsMcpServer::local_signing_from_config(&unsigned_path).is_err());
    let mut tampered: Value = serde_json::from_str(&original).unwrap();
    tampered["jacs_data_directory"] = json!("different-data");
    let tampered_path = base.join("tampered.json");
    std::fs::write(&tampered_path, serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(JacsMcpServer::local_signing_from_config(&tampered_path).is_err());
}

#[tokio::test]
#[serial_test::serial(mcp_local_signing_env)]
async fn startup_captures_config_and_password_instead_of_later_environment_overrides() {
    let (config, base) = support::prepare_temp_workspace();
    let _workspace = Workspace(base.clone());
    let _password = support::ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", support::TEST_PASSWORD);
    let _data =
        support::ScopedEnvVar::set("JACS_DATA_DIRECTORY", base.join("not-the-granted-root"));
    let _key = support::ScopedEnvVar::set("JACS_KEY_DIRECTORY", base.join("not-the-granted-key"));
    let server =
        JacsMcpServer::local_signing_from_config(&config).expect("file-only configuration");
    let _changed_password =
        support::ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", "wrong-after-startup");
    let _changed_config =
        support::ScopedEnvVar::set("JACS_CONFIG", base.join("missing-after-startup.json"));
    let result = server
        .jacs_sign_document(Parameters(jacs_mcp::tools::SignDocumentParams {
            content: "{\"hello\":\"stable identity\"}".to_string(),
            content_type: None,
        }))
        .await;
    let result: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(result["success"], true, "{result}");
    assert!(!base.join("not-the-granted-root").exists());
    assert!(!base.join("not-the-granted-key").exists());
}

#[tokio::test]
#[serial_test::serial(mcp_local_signing_env)]
async fn oversized_arguments_and_later_network_opt_in_are_rejected_before_signing() {
    let (config, base) = support::prepare_temp_workspace();
    let _workspace = Workspace(base.clone());
    let _password = support::ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", support::TEST_PASSWORD);
    let server = JacsMcpServer::local_signing_from_config(&config).unwrap();
    let documents_before = std::fs::read_dir(base.join("documents"))
        .map(|items| items.count())
        .unwrap_or(0);
    let result = server
        .jacs_sign_document(Parameters(jacs_mcp::tools::SignDocumentParams {
            content: json!({ "too_large": "x".repeat(1024 * 1024) }).to_string(),
            content_type: None,
        }))
        .await;
    let result: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(result["success"], false);
    assert!(result["message"].as_str().unwrap().contains("1 MiB"));

    let _network = support::ScopedEnvVar::set("JACS_ALLOW_NETWORK", "true");
    let result = server
        .jacs_sign_document(Parameters(jacs_mcp::tools::SignDocumentParams {
            content: "{}".to_string(),
            content_type: None,
        }))
        .await;
    let result: Value = serde_json::from_str(&result).unwrap();
    assert_eq!(result["success"], false);
    assert!(result["message"].as_str().unwrap().contains("offline"));
    assert!(JacsMcpServer::local_signing_from_config(&config).is_err());
    let documents_after = std::fs::read_dir(base.join("documents"))
        .map(|items| items.count())
        .unwrap_or(0);
    assert_eq!(documents_after, documents_before);
}

#[test]
#[cfg(unix)]
#[serial_test::serial(mcp_local_signing_env)]
fn symlink_config_is_rejected_before_resolving_a_password() {
    let (config, base) = support::prepare_temp_workspace();
    let _workspace = Workspace(base.clone());
    let link = base.join("linked.config.json");
    std::os::unix::fs::symlink(&config, &link).unwrap();
    let _password = support::ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", "");
    let error = match JacsMcpServer::local_signing_from_config(&link) {
        Ok(_) => panic!("symlinked config must not authorize a signer"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("regular file, not a symlink"),
        "{error}"
    );
}

#[test]
#[serial_test::serial(mcp_local_signing_env)]
fn mismatched_encrypted_private_key_cannot_authorize_startup() {
    let (config, base) = support::prepare_temp_workspace();
    let _workspace = Workspace(base.clone());
    let (other_config, other_base) = support::prepare_temp_workspace();
    let _other_workspace = Workspace(other_base.clone());
    let selected: Value = serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
    let other: Value =
        serde_json::from_str(&std::fs::read_to_string(&other_config).unwrap()).unwrap();
    let selected_private = base.join("jacs_keys").join(
        selected["jacs_agent_private_key_filename"]
            .as_str()
            .unwrap(),
    );
    let other_private = other_base
        .join("jacs_keys")
        .join(other["jacs_agent_private_key_filename"].as_str().unwrap());
    // Both fixture files remain encrypted with the same synthetic test password.
    std::fs::copy(other_private, selected_private).unwrap();
    let _password = support::ScopedEnvVar::set("JACS_PRIVATE_KEY_PASSWORD", support::TEST_PASSWORD);
    let error = match JacsMcpServer::local_signing_from_config(&config) {
        Ok(_) => panic!("mismatched private/public pair must fail startup"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("does not match the configured public identity"),
        "{error}"
    );
}
