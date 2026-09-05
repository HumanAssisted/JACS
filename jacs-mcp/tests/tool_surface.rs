#![cfg(feature = "mcp")]

use jacs_binding_core::AgentWrapper;
use rmcp::ServerHandler;

#[cfg(not(feature = "full-tools"))]
const CORE_TOOL_COUNT: usize = 25;
#[cfg(feature = "full-tools")]
const FULL_TOOL_COUNT: usize = 42;

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
    assert!(names.contains(&"jacs_w3c_export_did"));
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
        (
            "W3C interop",
            6,
            &[
                "jacs_w3c_export_did",
                "jacs_w3c_export_did_document",
                "jacs_w3c_export_agent_description",
                "jacs_w3c_generate_well_known",
                "jacs_w3c_sign_request",
                "jacs_w3c_verify_request",
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
        "jacs_apply_agreement_v2",
        "jacs_assess_a2a_agent",
        "jacs_attest_create",
        "jacs_attest_export_dsse",
        "jacs_attest_lift",
        "jacs_attest_verify",
        "jacs_check_agreement",
        "jacs_create_agent",
        "jacs_create_agreement",
        "jacs_create_agreement_v2",
        "jacs_detect_agreement_v2_branch_conflict",
        "jacs_export_agent",
        "jacs_export_agent_card",
        "jacs_extract_media_signature",
        "jacs_generate_well_known",
        "jacs_get_trusted_agent",
        "jacs_is_trusted",
        "jacs_list_trusted_agents",
        "jacs_merge_agreement_v2_transcript_branches",
        "jacs_reencrypt_key",
        "jacs_resolve_agreement_v2_branch_conflict",
        "jacs_rotate_keys",
        "jacs_search",
        "jacs_sign_agreement",
        "jacs_sign_agreement_v2",
        "jacs_sign_document",
        "jacs_sign_image",
        "jacs_sign_text",
        "jacs_trust_agent",
        "jacs_untrust_agent",
        "jacs_verify_a2a_artifact",
        "jacs_verify_agreement_v2",
        "jacs_verify_document",
        "jacs_verify_image",
        "jacs_verify_text",
        "jacs_w3c_export_agent_description",
        "jacs_w3c_export_did",
        "jacs_w3c_export_did_document",
        "jacs_w3c_generate_well_known",
        "jacs_w3c_sign_request",
        "jacs_w3c_verify_request",
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
        "jacs_w3c_export_agent_description",
        "jacs_w3c_export_did",
        "jacs_w3c_export_did_document",
        "jacs_w3c_generate_well_known",
        "jacs_w3c_sign_request",
        "jacs_w3c_verify_request",
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
            .contains("jacs_verify_document")
    );
    assert!(
        !info
            .instructions
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

    let verify_server =
        jacs_mcp::JacsMcpServer::with_profile(AgentWrapper::new(), Profile::VerifyOnly);
    let verify_tools = verify_server.active_tools();
    let verify_names: Vec<&str> = verify_tools.iter().map(|t| t.name.as_ref()).collect();

    assert!(!verify_names.contains(&"jacs_sign_document"));
    assert!(!verify_names.contains(&"jacs_trust_agent"));
    assert_eq!(verify_names, vec!["jacs_verify_document"]);

    for name in &verify_names {
        assert!(!name.starts_with("jacs_message_"));
        assert!(!name.starts_with("jacs_memory_"));
        assert!(!name.starts_with("jacs_audit"));
        assert!(!name.ends_with("_state"));
        assert!(!name.contains("_state"));
        assert!(
            !name.starts_with("jacs_create_agreement")
                && !name.starts_with("jacs_sign_agreement")
                && !name.starts_with("jacs_check_agreement"),
            "verify-only profile should not contain agreement tool: {name}"
        );
    }
}

/// P2 FR19 guardrail (positive statement): every P2 ES256 ecosystem
/// export — JWKS, compatibility key binding, AP2 mandate, Agreement-v2
/// VC, and the DID-document compat entries — ships as CLI + binding
/// surface ONLY. The MCP tool surface must stay free of them in every
/// feature combination; a tool matching these fragments means FR19 was
/// violated and `cli_mcp_alignment.json` / this test must be revisited
/// together.
#[test]
fn p2_ecosystem_exports_are_cli_only_never_mcp_tools() {
    let names = sorted_tool_names();

    for fragment in [
        "jwks",
        "compat",
        "binding",
        "ecosystem",
        "ap2",
        "mandate",
        "agreement_vc",
        "export_vc",
    ] {
        assert!(
            !names.iter().any(|name| name.contains(fragment)),
            "FR19: P2 exports are CLI-only; found MCP tool matching '{fragment}' in: {names:?}"
        );
    }

    // The pre-P2 W3C export tools are the only DID-shaped MCP surface and
    // they stay: P2 changed what the library puts INSIDE the DID document
    // (scope-gated ES256 entries), not the MCP tool list.
    assert!(names.contains(&"jacs_w3c_export_did_document".to_string()));
}

/// P2 identity-export error contract: MCP has NO identity-export tool for
/// the ES256 compatibility surfaces (previous assertion), so there is no
/// MCP-side error payload to type — the actionable typed errors (e.g.
/// `KeyNotFound` pointing at `jacs agent add-compat-key`, scope denials
/// naming the missing scope) are exercised on the CLI and binding
/// surfaces (`jacs-cli/tests/mcp_observability_tests.rs`,
/// `jacs/tests/compatibility_observability.rs`). This test pins that
/// absence explicitly: adding an MCP identity-export tool later must
/// bring its error contract (and FR19) back into review.
#[test]
fn identity_export_error_contract_lives_on_cli_because_mcp_has_no_such_tool() {
    let names = sorted_tool_names();

    for would_be_tool in [
        "jacs_export_compatibility_jwks",
        "jacs_export_compat_binding",
        "jacs_issue_compat_binding",
        "jacs_add_compat_key",
    ] {
        assert!(
            !names.contains(&would_be_tool.to_string()),
            "MCP unexpectedly grew P2 identity-export tool '{would_be_tool}'; \
             its error contract must be typed and FR19 revisited"
        );
    }
}
