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
