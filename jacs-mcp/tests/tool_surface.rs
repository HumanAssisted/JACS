#![cfg(feature = "mcp")]

use jacs_binding_core::AgentWrapper;
use rmcp::ServerHandler;

/// With default features (core-tools), exactly 28 core tools are registered.
#[test]
fn default_features_register_core_tools() {
    let tools = jacs_mcp::JacsMcpServer::tools();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();

    // Core: state(6) + document(3) + trust(5) + audit(4) + memory(5) + search(1) + key(4) = 28
    let expected_core_count = 28;

    // With default features only core tools are registered.
    // If full-tools is also enabled, advanced tools appear too.
    #[cfg(not(feature = "full-tools"))]
    assert_eq!(
        tools.len(),
        expected_core_count,
        "default features should expose exactly {} core tools, got {}",
        expected_core_count,
        tools.len()
    );

    // Core tools must always be present
    assert!(names.contains(&"jacs_sign_state"));
    assert!(names.contains(&"jacs_list_state"));
    assert!(names.contains(&"jacs_sign_document"));
    assert!(names.contains(&"jacs_trust_agent"));
    assert!(names.contains(&"jacs_audit"));
    assert!(names.contains(&"jacs_memory_save"));
    assert!(names.contains(&"jacs_search"));
    assert!(names.contains(&"jacs_reencrypt_key"));
}

/// Per-category tool count snapshot for core families.
///
/// Categories are defined by the tool name prefix convention.
#[test]
fn per_category_core_tool_counts() {
    let tools = jacs_mcp::JacsMcpServer::tools();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();

    // Core categories only (always present with default features)
    let core_categories: &[(&str, usize, &[&str])] = &[
        (
            "state",
            6,
            &[
                "jacs_sign_state",
                "jacs_verify_state",
                "jacs_load_state",
                "jacs_update_state",
                "jacs_list_state",
                "jacs_adopt_state",
            ],
        ),
        (
            "document",
            3,
            &[
                "jacs_sign_document",
                "jacs_verify_document",
                "jacs_create_agent",
            ],
        ),
        (
            "trust store",
            5,
            &[
                "jacs_trust_agent",
                "jacs_untrust_agent",
                "jacs_list_trusted_agents",
                "jacs_is_trusted",
                "jacs_get_trusted_agent",
            ],
        ),
        ("security audit", 1, &["jacs_audit"]),
        (
            "audit trail",
            3,
            &["jacs_audit_log", "jacs_audit_query", "jacs_audit_export"],
        ),
        (
            "memory",
            5,
            &[
                "jacs_memory_save",
                "jacs_memory_recall",
                "jacs_memory_list",
                "jacs_memory_forget",
                "jacs_memory_update",
            ],
        ),
        ("search", 1, &["jacs_search"]),
        (
            "key management / A2A discovery",
            4,
            &[
                "jacs_reencrypt_key",
                "jacs_export_agent_card",
                "jacs_generate_well_known",
                "jacs_export_agent",
            ],
        ),
    ];

    for (category, expected_count, expected_members) in core_categories {
        for member in *expected_members {
            assert!(
                names.contains(member),
                "category '{}': expected tool '{}' is missing from the tool surface",
                category,
                member,
            );
        }
        assert_eq!(
            expected_members.len(),
            *expected_count,
            "category '{}': member list length does not match expected count",
            category,
        );
    }
}

/// Advanced families: only present when their feature flags are enabled.
#[cfg(feature = "full-tools")]
#[test]
fn full_tools_registers_all_42() {
    let tools = jacs_mcp::JacsMcpServer::tools();
    let mut names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    names.sort();

    assert_eq!(tools.len(), 42, "full-tools should expose all 42 tools");

    let expected: Vec<&str> = vec![
        "jacs_adopt_state",
        "jacs_assess_a2a_agent",
        "jacs_attest_create",
        "jacs_attest_export_dsse",
        "jacs_attest_lift",
        "jacs_attest_verify",
        "jacs_audit",
        "jacs_audit_export",
        "jacs_audit_log",
        "jacs_audit_query",
        "jacs_check_agreement",
        "jacs_create_agent",
        "jacs_create_agreement",
        "jacs_export_agent",
        "jacs_export_agent_card",
        "jacs_generate_well_known",
        "jacs_get_trusted_agent",
        "jacs_is_trusted",
        "jacs_list_state",
        "jacs_list_trusted_agents",
        "jacs_load_state",
        "jacs_memory_forget",
        "jacs_memory_list",
        "jacs_memory_recall",
        "jacs_memory_save",
        "jacs_memory_update",
        "jacs_message_agree",
        "jacs_message_receive",
        "jacs_message_send",
        "jacs_message_update",
        "jacs_reencrypt_key",
        "jacs_search",
        "jacs_sign_agreement",
        "jacs_sign_document",
        "jacs_sign_state",
        "jacs_trust_agent",
        "jacs_untrust_agent",
        "jacs_update_state",
        "jacs_verify_a2a_artifact",
        "jacs_verify_document",
        "jacs_verify_state",
        "jacs_wrap_a2a_artifact",
    ];

    assert_eq!(
        names, expected,
        "tool name snapshot mismatch; update expected list if changes are intentional"
    );
}

/// Sorted tool name snapshot for core tools only (default features).
#[cfg(not(feature = "full-tools"))]
#[test]
fn tool_names_snapshot_core_sorted() {
    let tools = jacs_mcp::JacsMcpServer::tools();
    let mut names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    names.sort();

    let expected: Vec<&str> = vec![
        "jacs_adopt_state",
        "jacs_audit",
        "jacs_audit_export",
        "jacs_audit_log",
        "jacs_audit_query",
        "jacs_create_agent",
        "jacs_export_agent",
        "jacs_export_agent_card",
        "jacs_generate_well_known",
        "jacs_get_trusted_agent",
        "jacs_is_trusted",
        "jacs_list_state",
        "jacs_list_trusted_agents",
        "jacs_load_state",
        "jacs_memory_forget",
        "jacs_memory_list",
        "jacs_memory_recall",
        "jacs_memory_save",
        "jacs_memory_update",
        "jacs_reencrypt_key",
        "jacs_search",
        "jacs_sign_document",
        "jacs_sign_state",
        "jacs_trust_agent",
        "jacs_untrust_agent",
        "jacs_update_state",
        "jacs_verify_document",
        "jacs_verify_state",
    ];

    assert_eq!(
        names, expected,
        "core tool name snapshot mismatch; update expected list if changes are intentional"
    );
}

#[test]
fn server_metadata_identifies_as_jacs_mcp() {
    let server = jacs_mcp::JacsMcpServer::new(AgentWrapper::new());
    let info = server.get_info();

    assert_eq!(info.server_info.name, "jacs-mcp");
    assert_eq!(info.server_info.title.as_deref(), Some("JACS MCP Server"));
    assert!(
        info.instructions
            .as_deref()
            .unwrap_or_default()
            .contains("jacs_sign_state")
    );
}

/// The active_tools() method respects the runtime profile.
#[test]
fn active_tools_respects_profile() {
    use jacs_mcp::Profile;

    let core_server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Core);
    let core_tools = core_server.active_tools();
    let core_names: Vec<&str> = core_tools.iter().map(|t| t.name.as_ref()).collect();

    // Core profile should only have core family tools
    assert!(core_names.contains(&"jacs_sign_state"));
    assert!(core_names.contains(&"jacs_memory_save"));
    assert!(core_names.contains(&"jacs_trust_agent"));

    // Advanced tools should not be present in core profile
    // (regardless of compile-time features)
    for name in &core_names {
        // messaging, agreement, a2a, attestation tools should be filtered out
        assert!(
            !name.starts_with("jacs_message_"),
            "core profile should not contain messaging tool: {}",
            name
        );
        assert!(
            !name.starts_with("jacs_create_agreement")
                && !name.starts_with("jacs_sign_agreement")
                && !name.starts_with("jacs_check_agreement"),
            "core profile should not contain agreement tool: {}",
            name
        );
    }
}
