#![cfg(feature = "mcp")]

use jacs_binding_core::AgentWrapper;
use rmcp::ServerHandler;

#[test]
fn canonical_tool_surface_is_stable() {
    let tools = jacs_mcp::JacsMcpServer::tools();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();

    assert_eq!(tools.len(), 33, "unexpected jacs-mcp tool count");
    assert!(names.contains(&"jacs_sign_state"));
    assert!(names.contains(&"jacs_list_state"));
    assert!(names.contains(&"jacs_wrap_a2a_artifact"));
    assert!(names.contains(&"jacs_attest_export_dsse"));
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
