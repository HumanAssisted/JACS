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
fn runtime_verify_only_profile_filters_every_privileged_tool() {
    let server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::VerifyOnly);
    let names: Vec<String> = server
        .active_tools()
        .iter()
        .map(|tool| tool.name.to_string())
        .collect();

    for forbidden in [
        "jacs_sign_document",
        "jacs_sign_agreement",
        "jacs_sign_agreement_v2",
        "jacs_trust_agent",
        "jacs_untrust_agent",
        "jacs_reencrypt_key",
        "jacs_rotate_keys",
    ] {
        assert!(!names.iter().any(|name| name == forbidden), "{forbidden}");
    }
    assert!(names.iter().any(|name| name == "jacs_verify_document"));
    assert_eq!(names, vec!["jacs_verify_document".to_string()]);
}

#[test]
fn runtime_default_profile_is_verify_only() {
    assert_eq!(Profile::default(), Profile::VerifyOnly);
}

#[test]
fn runtime_profile_parse_is_exact_and_closed() {
    assert_eq!(Profile::parse("verify-only").unwrap(), Profile::VerifyOnly);
    assert_eq!(Profile::parse("local-sign").unwrap(), Profile::LocalSign);
    assert_eq!(Profile::parse("trust-admin").unwrap(), Profile::TrustAdmin);
    assert_eq!(Profile::parse("legacy-core").unwrap(), Profile::LegacyCore);
    for value in ["core", "full", "Verify-Only", " verify-only"] {
        assert!(Profile::parse(value).is_err(), "{value:?}");
    }
}

#[test]
fn runtime_unknown_profile_is_rejected() {
    for value in ["unknown", "", "  "] {
        let error = Profile::parse(value).expect_err("invalid profile must fail closed");
        assert_eq!(error.value(), value);
        assert!(error.to_string().contains("expected exactly"));
    }
}

#[test]
fn privileged_profile_name_is_not_authority() {
    assert_eq!(
        Profile::resolve(Some("local-sign")).unwrap(),
        Profile::LocalSign
    );
    assert_eq!(
        Profile::LocalSign.tools(),
        Profile::VerifyOnly.tools(),
        "eligible local profile still needs the explicit signed-config constructor"
    );
    for profile in [Profile::TrustAdmin, Profile::LegacyCore] {
        let error = Profile::resolve(Some(profile.as_str()))
            .expect_err("privileged startup needs the TP-39 broker");
        assert_eq!(error.value(), profile.as_str());
        assert!(
            error
                .to_string()
                .contains("capability/status/approval WAL broker")
        );
    }
}

#[test]
#[serial(mcp_profile_env)]
fn runtime_env_var_and_default_resolution() {
    unsafe { std::env::set_var("JACS_MCP_PROFILE", "verify-only") };
    let profile = Profile::resolve(None).unwrap();
    assert_eq!(profile, Profile::VerifyOnly);

    unsafe { std::env::remove_var("JACS_MCP_PROFILE") };
    let profile = Profile::resolve(None).unwrap();
    assert_eq!(profile, Profile::VerifyOnly);

    unsafe { std::env::set_var("JACS_MCP_PROFILE", "") };
    assert!(Profile::resolve(None).is_err());

    unsafe { std::env::remove_var("JACS_MCP_PROFILE") };
}

#[test]
#[serial(mcp_profile_env)]
fn runtime_invalid_env_and_cli_profiles_are_rejected() {
    unsafe { std::env::set_var("JACS_MCP_PROFILE", "nonsense") };
    let env_error = Profile::resolve(None).expect_err("invalid env profile must fail");
    assert_eq!(env_error.value(), "nonsense");
    assert_eq!(
        Profile::resolve(Some("verify-only")).expect("valid CLI profile must override invalid env"),
        Profile::VerifyOnly
    );

    unsafe { std::env::set_var("JACS_MCP_PROFILE", "verify-only") };
    let cli_error = Profile::resolve(Some("nonsense"))
        .expect_err("invalid CLI profile must fail instead of using the env");
    assert_eq!(cli_error.value(), "nonsense");

    unsafe { std::env::remove_var("JACS_MCP_PROFILE") };
}

#[test]
#[serial(mcp_profile_env)]
fn server_new_is_explicitly_verify_only_even_when_env_requests_privilege() {
    unsafe { std::env::set_var("JACS_MCP_PROFILE", "local-sign") };
    let server = jacs_mcp::JacsMcpServer::new(AgentWrapper::new());
    assert_eq!(server.profile(), &Profile::VerifyOnly);
    unsafe { std::env::remove_var("JACS_MCP_PROFILE") };
}

#[test]
fn programmatic_privileged_profile_stays_verification_only() {
    let baseline = Profile::VerifyOnly.tools();
    for profile in [Profile::LocalSign, Profile::TrustAdmin, Profile::LegacyCore] {
        let server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), profile);
        assert_eq!(server.profile(), &profile);
        assert_eq!(server.active_tools(), baseline);
    }
}

#[test]
fn verify_only_profile_excludes_mutation_and_retired_tools() {
    let tools = Profile::VerifyOnly.tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    for name in &names {
        assert!(!name.starts_with("jacs_message_"));
        assert!(!name.starts_with("jacs_memory_"));
        assert!(!name.starts_with("jacs_audit"));
        assert!(!name.contains("_state"));
        assert!(!name.starts_with("jacs_create_agreement"));
        assert!(!name.starts_with("jacs_sign_agreement"));
        assert!(!name.starts_with("jacs_check_agreement"));
        assert!(!name.starts_with("jacs_trust_agent"));
        assert!(!name.starts_with("jacs_untrust_agent"));
        assert!(!name.starts_with("jacs_reencrypt_key"));
    }
}

#[test]
fn verify_only_profile_contains_only_explicit_key_document_verification() {
    let tools = Profile::VerifyOnly.tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    assert_eq!(names, vec!["jacs_verify_document"]);
}

#[test]
fn static_tools_vs_instance_active_tools() {
    let static_tools = jacs_mcp::JacsMcpServer::tools();
    let verify_server =
        jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::VerifyOnly);
    let active = verify_server.active_tools();

    assert!(active.len() <= static_tools.len());
}

#[test]
fn server_instructions_are_generated_from_active_tools() {
    let verify_server =
        jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::VerifyOnly);
    let verify_instructions = verify_server
        .get_info()
        .instructions
        .expect("verify-only instructions");
    assert!(verify_instructions.contains("profile 'verify-only'"));
    for tool in verify_server.active_tools() {
        assert!(
            verify_instructions.contains(tool.name.as_ref()),
            "instructions omitted active tool {}",
            tool.name
        );
    }

    for tool in jacs_mcp::JacsMcpServer::tools() {
        if !verify_server
            .active_tools()
            .iter()
            .any(|active| active.name == tool.name)
        {
            assert!(
                !verify_instructions.contains(tool.name.as_ref()),
                "verify-only instructions advertised inactive tool {}",
                tool.name
            );
        }
    }
}
