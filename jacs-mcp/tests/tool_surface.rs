#![cfg(feature = "mcp")]

use jacs_binding_core::AgentWrapper;
use rmcp::ServerHandler;

#[test]
fn canonical_tool_surface_is_stable() {
    let tools = jacs_mcp::JacsMcpServer::tools();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();

    assert_eq!(tools.len(), 42, "unexpected jacs-mcp tool count");
    assert!(names.contains(&"jacs_sign_state"));
    assert!(names.contains(&"jacs_list_state"));
    assert!(names.contains(&"jacs_wrap_a2a_artifact"));
    assert!(names.contains(&"jacs_attest_export_dsse"));
}

/// Per-category tool count snapshot.
///
/// Categories are defined by the tool name prefix convention. If a tool is
/// added, removed, or re-categorized, THIS test should fail and must be
/// updated intentionally. This documents the Phase 0 baseline for
/// Phase 7's narrowing work (TASK_004 / ARCHITECTURE_UPGRADE.md).
#[test]
fn per_category_tool_counts_match_baseline() {
    let tools = jacs_mcp::JacsMcpServer::tools();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();

    // Category definitions: (category_label, expected_count, expected_members)
    let categories: &[(&str, usize, &[&str])] = &[
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
        (
            "agent management",
            2,
            &["jacs_create_agent", "jacs_reencrypt_key"],
        ),
        ("security audit", 1, &["jacs_audit"]),
        (
            "audit trail",
            3,
            &["jacs_audit_log", "jacs_audit_query", "jacs_audit_export"],
        ),
        ("search", 1, &["jacs_search"]),
        (
            "messaging",
            4,
            &[
                "jacs_message_send",
                "jacs_message_update",
                "jacs_message_agree",
                "jacs_message_receive",
            ],
        ),
        (
            "agreements",
            3,
            &[
                "jacs_create_agreement",
                "jacs_sign_agreement",
                "jacs_check_agreement",
            ],
        ),
        (
            "document",
            2,
            &["jacs_sign_document", "jacs_verify_document"],
        ),
        (
            "A2A",
            3,
            &[
                "jacs_wrap_a2a_artifact",
                "jacs_verify_a2a_artifact",
                "jacs_assess_a2a_agent",
            ],
        ),
        (
            "A2A discovery / key export",
            3,
            &[
                "jacs_export_agent_card",
                "jacs_generate_well_known",
                "jacs_export_agent",
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
        (
            "attestation",
            4,
            &[
                "jacs_attest_create",
                "jacs_attest_verify",
                "jacs_attest_lift",
                "jacs_attest_export_dsse",
            ],
        ),
    ];

    let mut accounted = 0usize;
    for (category, expected_count, expected_members) in categories {
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
        accounted += expected_count;
    }

    // Every tool must be accounted for in exactly one category.
    assert_eq!(
        accounted,
        names.len(),
        "per-category member count ({}) does not equal total tool count ({}); \
         a tool was added or removed without updating this snapshot",
        accounted,
        names.len(),
    );
}

/// Full sorted tool name list snapshot.
///
/// This is the most granular snapshot: any tool add/remove/rename causes a
/// clear diff. Update this list intentionally when the tool surface changes.
#[test]
fn tool_names_snapshot_is_sorted_and_complete() {
    let tools = jacs_mcp::JacsMcpServer::tools();
    let mut names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    names.sort();

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
