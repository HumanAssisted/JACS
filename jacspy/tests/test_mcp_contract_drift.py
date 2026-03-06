"""Drift checks for Python MCP adapters against the canonical Rust contract."""

import inspect
import json
from pathlib import Path

from jacs.adapters.mcp import register_a2a_tools, register_jacs_tools, register_trust_tools
from jacs.client import JacsClient


CONTRACT_PATH = (
    Path(__file__).resolve().parents[2]
    / "jacs-mcp"
    / "contract"
    / "jacs-mcp-contract.json"
)

EXPECTED_CANONICAL_TOOL_NAMES = {
    "jacs_sign_document",
    "jacs_verify_document",
    "jacs_create_agreement",
    "jacs_sign_agreement",
    "jacs_check_agreement",
    "jacs_audit",
    "jacs_export_agent",
    "jacs_export_agent_card",
    "jacs_wrap_a2a_artifact",
    "jacs_verify_a2a_artifact",
    "jacs_assess_a2a_agent",
    "jacs_trust_agent",
    "jacs_untrust_agent",
    "jacs_list_trusted_agents",
    "jacs_get_trusted_agent",
    "jacs_is_trusted",
}

EXPECTED_COMPATIBILITY_TOOL_NAMES = {
    "jacs_sign_file",
    "jacs_verify_self",
    "jacs_agent_info",
    "jacs_share_public_key",
    "jacs_share_agent",
    "jacs_get_agent_card",
    "jacs_sign_artifact",
    "jacs_assess_remote_agent",
    "jacs_trust_agent_with_key",
    "jacs_list_trusted",
}

EXPECTED_SHAPE_MATCH_TOOL_NAMES = {
    "jacs_export_agent",
    "jacs_assess_a2a_agent",
    "jacs_trust_agent",
    "jacs_untrust_agent",
    "jacs_list_trusted_agents",
    "jacs_get_trusted_agent",
    "jacs_is_trusted",
}

EXPECTED_SHAPE_DRIFT_TOOL_NAMES = EXPECTED_CANONICAL_TOOL_NAMES - EXPECTED_SHAPE_MATCH_TOOL_NAMES


class FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, name: str = "", description: str = ""):
        def decorator(fn):
            self.tools[name] = {"fn": fn, "description": description}
            return fn

        return decorator


def _canonical_tools():
    contract = json.loads(CONTRACT_PATH.read_text())
    return {tool["name"]: tool for tool in contract["tools"]}


def _python_signature_shape(fn):
    signature = inspect.signature(fn)
    properties = []
    required = []

    for param in signature.parameters.values():
        if param.kind not in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            continue
        properties.append(param.name)
        if param.default is inspect.Signature.empty:
            required.append(param.name)

    return sorted(properties), sorted(required)


def _canonical_shape(tool):
    schema = tool["input_schema"]
    return (
        sorted(schema.get("properties", {}).keys()),
        sorted(schema.get("required", [])),
    )


def _registered_tools():
    client = JacsClient.ephemeral()
    mcp = FakeMCP()
    register_jacs_tools(mcp, client=client)
    register_a2a_tools(mcp, client=client)
    register_trust_tools(mcp, client=client)
    return mcp.tools


def test_python_mcp_tools_are_canonical_or_explicitly_compatibility_only():
    registered = _registered_tools()
    canonical = _canonical_tools()

    published_names = set(registered)
    canonical_names = {name for name in published_names if name in canonical}
    compatibility_names = published_names - canonical_names

    assert canonical_names == EXPECTED_CANONICAL_TOOL_NAMES
    assert compatibility_names == EXPECTED_COMPATIBILITY_TOOL_NAMES


def test_python_mcp_canonical_schema_matches_or_is_explicitly_tracked():
    registered = _registered_tools()
    canonical = _canonical_tools()

    matching = set()
    drifting = set()

    for name in EXPECTED_CANONICAL_TOOL_NAMES:
        python_shape = _python_signature_shape(registered[name]["fn"])
        rust_shape = _canonical_shape(canonical[name])
        if python_shape == rust_shape:
            matching.add(name)
        else:
            drifting.add(name)

    assert matching == EXPECTED_SHAPE_MATCH_TOOL_NAMES
    assert drifting == EXPECTED_SHAPE_DRIFT_TOOL_NAMES
