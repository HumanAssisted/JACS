use jacs::simple::{CreateAgentParams, SimpleAgent};
use jacs_binding_core::{AgentWrapper, DocumentServiceWrapper};
use serde_json::Value;
use serial_test::serial;
use std::fs;

const TEST_PASSWORD: &str = "TestP@ss123!#";

fn sqlite_ready_agent() -> (AgentWrapper, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().expect("create tempdir");
    let data_dir = tmp.path().join("jacs_data");
    let key_dir = tmp.path().join("jacs_keys");
    let config_path = tmp.path().join("jacs.config.json");

    let params = CreateAgentParams::builder()
        .name("binding-doc-wrapper-sqlite")
        .password(TEST_PASSWORD)
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .default_storage("fs")
        .build();

    let (_agent, _info) =
        SimpleAgent::create_with_params(params).expect("create_with_params should succeed");

    let mut config_json: Value =
        serde_json::from_str(&fs::read_to_string(&config_path).expect("read generated config"))
            .expect("parse generated config");
    config_json["jacs_default_storage"] = Value::String("rusqlite".to_string());
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&config_json).expect("serialize config"),
    )
    .expect("write updated config");

    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", TEST_PASSWORD);
    }

    let wrapper = AgentWrapper::new();
    wrapper
        .load(config_path.to_string_lossy().into_owned())
        .expect("agent load should succeed");

    (wrapper, tmp)
}

#[test]
#[serial]
fn from_agent_wrapper_uses_sqlite_search_backend() {
    let (agent, _tmp) = sqlite_ready_agent();
    let docs = DocumentServiceWrapper::from_agent_wrapper(&agent)
        .expect("document service wrapper should resolve sqlite backend");

    docs.create_json(r#"{"content":"bindingsqliteprobe alpha"}"#, None)
        .expect("create first doc");
    docs.create_json(r#"{"content":"bindingsqliteprobe beta"}"#, None)
        .expect("create second doc");

    let result_json = docs
        .search_json(r#"{"query":"bindingsqliteprobe","limit":10,"offset":0}"#)
        .expect("search_json should succeed");
    let result: Value = serde_json::from_str(&result_json).expect("search result should be JSON");

    assert_eq!(result["method"], "FullText");
    assert!(
        result["results"]
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false),
        "sqlite-backed search should return at least one hit: {}",
        result
    );
}
