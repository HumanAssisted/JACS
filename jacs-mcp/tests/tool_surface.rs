#![cfg(feature = "mcp")]

use jacs_binding_core::AgentWrapper;
use rmcp::ServerHandler;

#[cfg(not(feature = "full-tools"))]
const CORE_TOOL_COUNT: usize = 19;
#[cfg(feature = "full-tools")]
const FULL_TOOL_COUNT: usize = 29;

fn sorted_tool_names() -> Vec<String> {
    let mut names: Vec<String> = jacs_mcp::JacsMcpServer::tools()
        .iter()
        .map(|tool| tool.name.to_string())
        .collect();
    names.sort();
    names
}

#[test]
fn default_features_register_core_tools() {
    let tools = jacs_mcp::JacsMcpServer::tools();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();

    #[cfg(not(feature = "full-tools"))]
    assert_eq!(
        tools.len(),
        CORE_TOOL_COUNT,
        "default features should expose exactly {CORE_TOOL_COUNT} core tools"
    );

    assert!(names.contains(&"jacs_sign_document"));
    assert!(names.contains(&"jacs_verify_document"));
    assert!(names.contains(&"jacs_trust_agent"));
    assert!(names.contains(&"jacs_search"));
    assert!(names.contains(&"jacs_reencrypt_key"));
    assert!(names.contains(&"jacs_sign_text"));
    assert!(names.contains(&"jacs_sign_image"));

    assert!(!names.iter().any(|name| name.contains("_state")));
    assert!(!names.iter().any(|name| name.starts_with("jacs_message_")));
    assert!(!names.iter().any(|name| name.starts_with("jacs_memory_")));
    assert!(!names.iter().any(|name| name.starts_with("jacs_audit")));
}

#[test]
fn per_category_core_tool_counts() {
    let tools = jacs_mcp::JacsMcpServer::tools();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();

    let core_categories: &[(&str, usize, &[&str])] = &[
        (
            "document",
            3,
            &[
                "jacs_sign_document",
                "jacs_verify_document",
                "jacs_create_agent",
            ],
        ),
        ("inline-text", 2, &["jacs_sign_text", "jacs_verify_text"]),
        (
            "media",
            3,
            &[
                "jacs_sign_image",
                "jacs_verify_image",
                "jacs_extract_media_signature",
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
        ("search", 1, &["jacs_search"]),
        (
            "key management / A2A discovery",
            5,
            &[
                "jacs_reencrypt_key",
                "jacs_rotate_keys",
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
                "category '{category}': expected tool '{member}' is missing"
            );
        }
        assert_eq!(
            expected_members.len(),
            *expected_count,
            "category '{category}': member list length does not match expected count",
        );
    }
}

#[cfg(feature = "full-tools")]
#[test]
fn full_tools_registers_all_current_tools() {
    assert_eq!(
        jacs_mcp::JacsMcpServer::tools().len(),
        FULL_TOOL_COUNT,
        "full-tools should expose all current tools"
    );

    let expected: Vec<String> = vec![
        "jacs_assess_a2a_agent",
        "jacs_attest_create",
        "jacs_attest_export_dsse",
        "jacs_attest_lift",
        "jacs_attest_verify",
        "jacs_check_agreement",
        "jacs_create_agent",
        "jacs_create_agreement",
        "jacs_export_agent",
        "jacs_export_agent_card",
        "jacs_extract_media_signature",
        "jacs_generate_well_known",
        "jacs_get_trusted_agent",
        "jacs_is_trusted",
        "jacs_list_trusted_agents",
        "jacs_reencrypt_key",
        "jacs_rotate_keys",
        "jacs_search",
        "jacs_sign_agreement",
        "jacs_sign_document",
        "jacs_sign_image",
        "jacs_sign_text",
        "jacs_trust_agent",
        "jacs_untrust_agent",
        "jacs_verify_a2a_artifact",
        "jacs_verify_document",
        "jacs_verify_image",
        "jacs_verify_text",
        "jacs_wrap_a2a_artifact",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    assert_eq!(sorted_tool_names(), expected);
}

#[cfg(not(feature = "full-tools"))]
#[test]
fn tool_names_snapshot_core_sorted() {
    let expected: Vec<String> = vec![
        "jacs_create_agent",
        "jacs_export_agent",
        "jacs_export_agent_card",
        "jacs_extract_media_signature",
        "jacs_generate_well_known",
        "jacs_get_trusted_agent",
        "jacs_is_trusted",
        "jacs_list_trusted_agents",
        "jacs_reencrypt_key",
        "jacs_rotate_keys",
        "jacs_search",
        "jacs_sign_document",
        "jacs_sign_image",
        "jacs_sign_text",
        "jacs_trust_agent",
        "jacs_untrust_agent",
        "jacs_verify_document",
        "jacs_verify_image",
        "jacs_verify_text",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    assert_eq!(sorted_tool_names(), expected);
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
            .contains("jacs_sign_document")
    );
    assert!(
        !info
            .instructions
            .as_deref()
            .unwrap_or_default()
            .contains("_state")
    );
}

#[test]
fn active_tools_respects_profile() {
    use jacs_mcp::Profile;

    let core_server = jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::Core);
    let core_tools = core_server.active_tools();
    let core_names: Vec<&str> = core_tools.iter().map(|t| t.name.as_ref()).collect();

    assert!(core_names.contains(&"jacs_sign_document"));
    assert!(core_names.contains(&"jacs_trust_agent"));
    assert!(core_names.contains(&"jacs_search"));

    for name in &core_names {
        assert!(!name.starts_with("jacs_message_"));
        assert!(!name.starts_with("jacs_memory_"));
        assert!(!name.starts_with("jacs_audit"));
        assert!(!name.ends_with("_state"));
        assert!(!name.contains("_state"));
        assert!(
            !name.starts_with("jacs_create_agreement")
                && !name.starts_with("jacs_sign_agreement")
                && !name.starts_with("jacs_check_agreement"),
            "core profile should not contain agreement tool: {name}"
        );
    }
}
