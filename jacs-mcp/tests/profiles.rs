//! Integration tests for compile-time and runtime tool profiles (TASK_039).
//!
//! These tests verify that:
//! - Feature flags control which tool families are compiled in
//! - The `Profile` enum correctly filters tools at runtime
//! - `JACS_MCP_PROFILE` env var and CLI flag resolution works
//! - Core vs Full profile boundaries are correct

#![cfg(feature = "mcp")]

use jacs_binding_core::AgentWrapper;
use jacs_mcp::Profile;

// =========================================================================
// Compile-time feature tests
// =========================================================================

/// With default features (`core-tools`), exactly 28 core tools are registered.
#[test]
fn compile_time_default_features_yield_core_tools() {
    let tools = jacs_mcp::JacsMcpServer::tools();

    // Core: state(6) + document(3) + trust(5) + audit(4) + memory(5) + search(1) + key(4) = 28
    #[cfg(not(feature = "full-tools"))]
    assert_eq!(
        tools.len(),
        28,
        "default features (core-tools) should register exactly 28 tools"
    );

    // If full-tools is enabled, all 42 tools are registered
    #[cfg(feature = "full-tools")]
    assert_eq!(
        tools.len(),
        42,
        "full-tools feature should register all 42 tools"
    );
}

/// Tool family features are additive: enabling one adds only its tools.
#[test]
fn compile_time_features_are_additive() {
    let tools = jacs_mcp::JacsMcpServer::tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    // State tools should always be present (part of core-tools default)
    #[cfg(feature = "state-tools")]
    {
        assert!(names.contains(&"jacs_sign_state"));
        assert!(names.contains(&"jacs_verify_state"));
        assert!(names.contains(&"jacs_load_state"));
        assert!(names.contains(&"jacs_update_state"));
        assert!(names.contains(&"jacs_list_state"));
        assert!(names.contains(&"jacs_adopt_state"));
    }

    // Memory tools should be present (part of core-tools default)
    #[cfg(feature = "memory-tools")]
    {
        assert!(names.contains(&"jacs_memory_save"));
        assert!(names.contains(&"jacs_memory_recall"));
        assert!(names.contains(&"jacs_memory_list"));
        assert!(names.contains(&"jacs_memory_forget"));
        assert!(names.contains(&"jacs_memory_update"));
    }

    // Messaging tools only present with messaging-tools feature
    #[cfg(feature = "messaging-tools")]
    {
        assert!(names.contains(&"jacs_message_send"));
        assert!(names.contains(&"jacs_message_update"));
        assert!(names.contains(&"jacs_message_agree"));
        assert!(names.contains(&"jacs_message_receive"));
    }
    #[cfg(not(feature = "messaging-tools"))]
    {
        assert!(!names.contains(&"jacs_message_send"));
    }

    // Agreement tools only present with agreement-tools feature
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

    // A2A tools only present with a2a-tools feature
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

    // Attestation tools only present with attestation-tools feature
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

// =========================================================================
// Runtime profile tests
// =========================================================================

/// `Profile::Core` filters out advanced tools even when compiled in.
#[test]
fn runtime_core_profile_filters_advanced_tools() {
    let server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Core);
    let tools = server.active_tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    // Core tools present
    assert!(names.contains(&"jacs_sign_state"));
    assert!(names.contains(&"jacs_memory_save"));
    assert!(names.contains(&"jacs_trust_agent"));
    assert!(names.contains(&"jacs_sign_document"));
    assert!(names.contains(&"jacs_audit"));
    assert!(names.contains(&"jacs_search"));
    assert!(names.contains(&"jacs_reencrypt_key"));

    // Advanced tools filtered out
    assert!(
        !names.contains(&"jacs_message_send"),
        "Core profile should not contain messaging tools"
    );
    assert!(
        !names.contains(&"jacs_create_agreement"),
        "Core profile should not contain agreement tools"
    );
    assert!(
        !names.contains(&"jacs_wrap_a2a_artifact"),
        "Core profile should not contain A2A tools"
    );
    assert!(
        !names.contains(&"jacs_attest_create"),
        "Core profile should not contain attestation tools"
    );
}

/// `Profile::Full` exposes all compiled-in tools.
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

/// Default profile (no explicit setting) is Core.
#[test]
fn runtime_default_profile_is_core() {
    assert_eq!(Profile::default(), Profile::Core);
}

/// Profile parsing is case-insensitive.
#[test]
fn runtime_profile_parse_case_insensitive() {
    assert_eq!(Profile::parse("full"), Profile::Full);
    assert_eq!(Profile::parse("Full"), Profile::Full);
    assert_eq!(Profile::parse("FULL"), Profile::Full);
    assert_eq!(Profile::parse("core"), Profile::Core);
    assert_eq!(Profile::parse("Core"), Profile::Core);
    assert_eq!(Profile::parse("CORE"), Profile::Core);
}

/// Unknown profile string defaults to Core (fail-safe).
#[test]
fn runtime_unknown_profile_defaults_to_core() {
    assert_eq!(Profile::parse("unknown"), Profile::Core);
    assert_eq!(Profile::parse(""), Profile::Core);
    assert_eq!(Profile::parse("  "), Profile::Core);
}

/// CLI flag takes priority over env var.
#[test]
fn runtime_cli_overrides_env_var() {
    let profile = Profile::resolve(Some("core"));
    assert_eq!(profile, Profile::Core);

    let profile = Profile::resolve(Some("full"));
    assert_eq!(profile, Profile::Full);
}

/// Env var and default resolution tests.
///
/// Combined into a single test to avoid parallel execution races on the
/// process-global JACS_MCP_PROFILE environment variable.
#[test]
fn runtime_env_var_and_default_resolution() {
    // Test 1: Env var sets profile
    unsafe { std::env::set_var("JACS_MCP_PROFILE", "full") };
    let profile = Profile::resolve(None);
    assert_eq!(
        profile,
        Profile::Full,
        "env var 'full' should resolve to Full"
    );

    // Test 2: CLI overrides env var
    let profile = Profile::resolve(Some("core"));
    assert_eq!(
        profile,
        Profile::Core,
        "CLI 'core' should override env var 'full'"
    );

    // Test 3: When env var is removed, default to Core
    unsafe { std::env::remove_var("JACS_MCP_PROFILE") };
    let profile = Profile::resolve(None);
    assert_eq!(profile, Profile::Core, "no config should default to Core");

    // Test 4: Empty env var defaults to Core
    unsafe { std::env::set_var("JACS_MCP_PROFILE", "") };
    let profile = Profile::resolve(None);
    assert_eq!(
        profile,
        Profile::Core,
        "empty env var should default to Core"
    );

    // Cleanup
    unsafe { std::env::remove_var("JACS_MCP_PROFILE") };
}

// =========================================================================
// Profile interaction with server
// =========================================================================

/// `with_profile` constructor stores the profile and uses it in `active_tools()`.
#[test]
fn server_with_profile_stores_and_uses_profile() {
    let core_server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Core);
    assert_eq!(core_server.profile(), &Profile::Core);

    let full_server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Full);
    assert_eq!(full_server.profile(), &Profile::Full);
}

// =========================================================================
// Task 007: Specific profile filtering verification tests
// =========================================================================

/// Core profile must exclude agreement and messaging tool names.
#[test]
fn core_profile_excludes_agreement_tools() {
    let core = Profile::Core;
    let tools = core.tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    for name in &names {
        assert!(
            !name.starts_with("jacs_agreement")
                && !name.starts_with("jacs_create_agreement")
                && !name.starts_with("jacs_sign_agreement")
                && !name.starts_with("jacs_check_agreement"),
            "Core profile should not contain agreement tool '{}'",
            name
        );
        assert!(
            !name.starts_with("jacs_message_"),
            "Core profile should not contain messaging tool '{}'",
            name
        );
    }
}

/// Full profile must include all compiled-in tools.
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

/// Core profile must include search and state tools.
#[test]
fn core_profile_includes_search_and_state_tools() {
    let core = Profile::Core;
    let tools = core.tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    assert!(
        names.contains(&"jacs_search"),
        "Core profile should contain jacs_search"
    );
    assert!(
        names.contains(&"jacs_sign_state"),
        "Core profile should contain jacs_sign_state"
    );
    assert!(
        names.contains(&"jacs_load_state"),
        "Core profile should contain jacs_load_state"
    );
}

/// `JacsMcpServer::tools()` (static) always returns all compiled-in tools,
/// while `active_tools()` (instance) respects the profile.
#[test]
fn static_tools_vs_instance_active_tools() {
    let static_tools = jacs_mcp::JacsMcpServer::tools();
    let core_server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Core);
    let active = core_server.active_tools();

    // Static tools include everything compiled in.
    // Active tools may be a subset if profile is Core.
    assert!(
        active.len() <= static_tools.len(),
        "active_tools should be a subset of tools()"
    );
}
