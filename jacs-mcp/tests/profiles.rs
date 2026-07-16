//! Integration tests for compile-time and runtime tool profiles.

#![cfg(feature = "mcp")]

use jacs_binding_core::AgentWrapper;
use jacs_mcp::Profile;
use rmcp::ServerHandler;
use serial_test::serial;

#[cfg(not(feature = "full-tools"))]
const CORE_TOOL_COUNT: usize = 25;
#[cfg(feature = "full-tools")]
const FULL_TOOL_COUNT: usize = 42;

#[test]
fn compile_time_default_features_yield_core_tools() {
    let tools = jacs_mcp::JacsMcpServer::tools();

    #[cfg(not(feature = "full-tools"))]
    assert_eq!(
        tools.len(),
        CORE_TOOL_COUNT,
        "default features should register exactly {CORE_TOOL_COUNT} tools"
    );

    #[cfg(feature = "full-tools")]
    assert_eq!(
        tools.len(),
        FULL_TOOL_COUNT,
        "full-tools should register all {FULL_TOOL_COUNT} current tools"
    );
}

#[test]
fn compile_time_features_are_additive() {
    let tools = jacs_mcp::JacsMcpServer::tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    assert!(names.contains(&"jacs_sign_document"));
    assert!(names.contains(&"jacs_verify_document"));
    assert!(names.contains(&"jacs_search"));
    assert!(names.contains(&"jacs_reencrypt_key"));
    assert!(names.contains(&"jacs_w3c_export_did"));

    assert!(!names.iter().any(|name| name.contains("_state")));
    assert!(!names.iter().any(|name| name.starts_with("jacs_message_")));
    assert!(!names.iter().any(|name| name.starts_with("jacs_memory_")));
    assert!(!names.iter().any(|name| name.starts_with("jacs_audit")));

    #[cfg(feature = "agreement-tools")]
    {
        assert!(names.contains(&"jacs_create_agreement"));
        assert!(names.contains(&"jacs_sign_agreement"));
        assert!(names.contains(&"jacs_check_agreement"));
    }
    #[cfg(not(feature = "agreement-tools"))]
    {
        assert!(!names.contains(&"jacs_create_agreement"));
    }

    #[cfg(feature = "a2a-tools")]
    {
        assert!(names.contains(&"jacs_wrap_a2a_artifact"));
        assert!(names.contains(&"jacs_verify_a2a_artifact"));
        assert!(names.contains(&"jacs_assess_a2a_agent"));
    }
    #[cfg(not(feature = "a2a-tools"))]
    {
        assert!(!names.contains(&"jacs_wrap_a2a_artifact"));
    }

    #[cfg(feature = "attestation-tools")]
    {
        assert!(names.contains(&"jacs_attest_create"));
        assert!(names.contains(&"jacs_attest_verify"));
        assert!(names.contains(&"jacs_attest_lift"));
        assert!(names.contains(&"jacs_attest_export_dsse"));
    }
    #[cfg(not(feature = "attestation-tools"))]
    {
        assert!(!names.contains(&"jacs_attest_create"));
    }
}

#[test]
fn runtime_core_profile_filters_advanced_tools() {
    let server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Core);
    let tools = server.active_tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    assert!(names.contains(&"jacs_trust_agent"));
    assert!(names.contains(&"jacs_sign_document"));
    assert!(names.contains(&"jacs_search"));
    assert!(names.contains(&"jacs_reencrypt_key"));

    assert!(!names.contains(&"jacs_create_agreement"));
    assert!(!names.contains(&"jacs_wrap_a2a_artifact"));
    assert!(!names.contains(&"jacs_attest_create"));
    assert!(!names.iter().any(|name| name.contains("_state")));
    assert!(!names.iter().any(|name| name.starts_with("jacs_message_")));
}

#[test]
fn runtime_full_profile_exposes_all_tools() {
    let server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Full);
    let full_tools = server.active_tools();
    let all_tools = jacs_mcp::JacsMcpServer::tools();

    assert_eq!(
        full_tools.len(),
        all_tools.len(),
        "Full profile should expose all compiled-in tools"
    );
}

#[test]
fn runtime_default_profile_is_core() {
    assert_eq!(Profile::default(), Profile::Core);
}

#[test]
fn runtime_profile_parse_case_insensitive() {
    assert_eq!(Profile::parse("full").unwrap(), Profile::Full);
    assert_eq!(Profile::parse("Full").unwrap(), Profile::Full);
    assert_eq!(Profile::parse("FULL").unwrap(), Profile::Full);
    assert_eq!(Profile::parse("core").unwrap(), Profile::Core);
    assert_eq!(Profile::parse("Core").unwrap(), Profile::Core);
    assert_eq!(Profile::parse("CORE").unwrap(), Profile::Core);
}

#[test]
fn runtime_unknown_profile_is_rejected() {
    for value in ["unknown", "", "  "] {
        let error = Profile::parse(value).expect_err("invalid profile must fail closed");
        assert_eq!(error.value(), value.trim());
        assert!(error.to_string().contains("expected 'core' or 'full'"));
    }
}

#[test]
fn runtime_cli_overrides_env_var() {
    let profile = Profile::resolve(Some("core")).unwrap();
    assert_eq!(profile, Profile::Core);

    let profile = Profile::resolve(Some("full")).unwrap();
    assert_eq!(profile, Profile::Full);
}

#[test]
#[serial(mcp_profile_env)]
fn runtime_env_var_and_default_resolution() {
    unsafe { std::env::set_var("JACS_MCP_PROFILE", "full") };
    let profile = Profile::resolve(None).unwrap();
    assert_eq!(profile, Profile::Full);

    let profile = Profile::resolve(Some("core")).unwrap();
    assert_eq!(profile, Profile::Core);

    unsafe { std::env::remove_var("JACS_MCP_PROFILE") };
    let profile = Profile::resolve(None).unwrap();
    assert_eq!(profile, Profile::Core);

    unsafe { std::env::set_var("JACS_MCP_PROFILE", "") };
    let profile = Profile::resolve(None).unwrap();
    assert_eq!(profile, Profile::Core);

    unsafe { std::env::remove_var("JACS_MCP_PROFILE") };
}

#[test]
#[serial(mcp_profile_env)]
fn runtime_invalid_env_and_cli_profiles_are_rejected() {
    unsafe { std::env::set_var("JACS_MCP_PROFILE", "nonsense") };
    let env_error = Profile::resolve(None).expect_err("invalid env profile must fail");
    assert_eq!(env_error.value(), "nonsense");
    assert_eq!(
        Profile::resolve(Some("core")).expect("valid CLI profile must override invalid env"),
        Profile::Core
    );

    unsafe { std::env::set_var("JACS_MCP_PROFILE", "full") };
    let cli_error = Profile::resolve(Some("nonsense"))
        .expect_err("invalid CLI profile must fail instead of using the env");
    assert_eq!(cli_error.value(), "nonsense");

    unsafe { std::env::remove_var("JACS_MCP_PROFILE") };
}

#[test]
#[serial(mcp_profile_env)]
fn server_new_is_explicitly_core_even_when_env_requests_full() {
    unsafe { std::env::set_var("JACS_MCP_PROFILE", "full") };
    let server = jacs_mcp::JacsMcpServer::new(AgentWrapper::new());
    assert_eq!(server.profile(), &Profile::Core);
    unsafe { std::env::remove_var("JACS_MCP_PROFILE") };
}

#[test]
fn server_with_profile_stores_and_uses_profile() {
    let core_server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Core);
    assert_eq!(core_server.profile(), &Profile::Core);

    let full_server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Full);
    assert_eq!(full_server.profile(), &Profile::Full);
}

#[test]
fn core_profile_excludes_advanced_and_retired_tools() {
    let tools = Profile::Core.tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    for name in &names {
        assert!(!name.starts_with("jacs_message_"));
        assert!(!name.starts_with("jacs_memory_"));
        assert!(!name.starts_with("jacs_audit"));
        assert!(!name.contains("_state"));
        assert!(!name.starts_with("jacs_create_agreement"));
        assert!(!name.starts_with("jacs_sign_agreement"));
        assert!(!name.starts_with("jacs_check_agreement"));
    }
}

#[test]
fn full_profile_includes_all_tools() {
    let full = Profile::Full;
    let full_tools = full.tools();
    let all = jacs_mcp::tools::all_classified_tools();

    assert_eq!(
        full_tools.len(),
        all.len(),
        "Full profile should include all compiled-in tools"
    );
}

#[test]
fn core_profile_includes_search_and_document_tools() {
    let tools = Profile::Core.tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    assert!(names.contains(&"jacs_search"));
    assert!(names.contains(&"jacs_sign_document"));
    assert!(names.contains(&"jacs_verify_document"));
}

#[test]
fn static_tools_vs_instance_active_tools() {
    let static_tools = jacs_mcp::JacsMcpServer::tools();
    let core_server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Core);
    let active = core_server.active_tools();

    assert!(active.len() <= static_tools.len());
}

#[test]
fn server_instructions_are_generated_from_active_tools() {
    let core_server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Core);
    let core_instructions = core_server
        .get_info()
        .instructions
        .expect("core instructions");
    assert!(core_instructions.contains("profile 'core'"));
    for tool in core_server.active_tools() {
        assert!(
            core_instructions.contains(tool.name.as_ref()),
            "instructions omitted active tool {}",
            tool.name
        );
    }

    for tool in jacs_mcp::JacsMcpServer::tools() {
        if !core_server
            .active_tools()
            .iter()
            .any(|active| active.name == tool.name)
        {
            assert!(
                !core_instructions.contains(tool.name.as_ref()),
                "core instructions advertised inactive tool {}",
                tool.name
            );
        }
    }

    let full_server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Full);
    let full_instructions = full_server
        .get_info()
        .instructions
        .expect("full instructions");
    assert!(full_instructions.contains("profile 'full'"));
    for tool in full_server.active_tools() {
        assert!(full_instructions.contains(tool.name.as_ref()));
    }
}
