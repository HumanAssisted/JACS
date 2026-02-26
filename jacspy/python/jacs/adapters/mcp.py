"""JACS MCP adapter — expose JACS operations as MCP tools.

Registers signing, verification, agreement, audit, A2A, and trust
tools with a FastMCP server so an LLM can call them directly.
Mirrors the Rust ``jacs-mcp`` tool surface.

Usage as tools (LLM-callable):
    from fastmcp import FastMCP
    from jacs.adapters.mcp import register_jacs_tools, register_a2a_tools

    mcp = FastMCP("my-server")
    register_jacs_tools(mcp)       # core signing/verification tools
    register_a2a_tools(mcp)        # A2A agent card + artifact tools
    register_trust_tools(mcp)      # trust store tools
    mcp.run()

Usage as middleware (sign all responses):
    from jacs.adapters.mcp import JacsMCPMiddleware

    mcp = FastMCP("my-server")
    mcp.add_middleware(JacsMCPMiddleware(client=client, a2a=True))
    mcp.run()

Requires: pip install jacs[mcp]   (fastmcp>=2.9)
"""

import json
import logging
import os
from typing import Any, List, Optional, Union

from .base import BaseJacsAdapter

logger = logging.getLogger("jacs.adapters.mcp")


def _is_untrust_allowed() -> bool:
    """Check if untrusting agents is allowed via environment variable.

    Mirrors the Rust MCP server's ``is_untrust_allowed()`` check.
    Untrusting requires explicit opt-in to prevent prompt injection
    attacks from removing trusted agents without user consent.
    """
    return os.environ.get("JACS_MCP_ALLOW_UNTRUST", "").lower() in ("true", "1")


def _validate_mcp_file_path(file_path: str) -> None:
    """Validate that a file path is safe for MCP tool use.

    Rejects absolute paths, parent-directory traversal, null bytes,
    and Windows drive-prefixed paths to prevent path traversal attacks
    via prompt injection.

    Raises:
        ValueError: If the path is unsafe.
    """
    if not file_path:
        raise ValueError("file_path cannot be empty")

    # Reject null bytes
    if "\0" in file_path:
        raise ValueError(f"file_path contains null byte: {file_path!r}")

    # Reject absolute paths (Unix and Windows)
    if file_path.startswith("/") or file_path.startswith("\\"):
        raise ValueError(
            f"Absolute paths are not allowed in MCP tools: {file_path!r}"
        )

    # Reject Windows drive-prefixed paths (e.g., C:\foo, D:/bar)
    if (
        len(file_path) >= 2
        and file_path[0].isalpha()
        and file_path[1] == ":"
    ):
        raise ValueError(
            f"Windows drive-prefixed paths are not allowed in MCP tools: {file_path!r}"
        )

    # Check each path segment for traversal
    for segment in file_path.replace("\\", "/").split("/"):
        if segment == "..":
            raise ValueError(
                f"Path traversal ('..') is not allowed in MCP tools: {file_path!r}"
            )
        if segment == ".":
            raise ValueError(
                f"Current-directory segment ('.') is not allowed in MCP tools: {file_path!r}"
            )


# ---------------------------------------------------------------------------
# Tool registration (LLM-callable tools)
# ---------------------------------------------------------------------------


def register_jacs_tools(
    mcp_server: Any,
    client: Optional[Any] = None,
    config_path: Optional[str] = None,
    strict: bool = False,
    *,
    tools: Optional[List[str]] = None,
) -> Any:
    """Register JACS operations as MCP tools on a FastMCP server.

    Args:
        mcp_server: A FastMCP server instance.
        client: An existing JacsClient. If None, one is created via
            quickstart.
        config_path: Path to jacs.config.json (used if no client).
        strict: Raise on failures instead of returning error JSON.
        tools: Optional list of tool names to register. If None, all
            tools are registered. Valid names: ``sign_document``,
            ``verify_document``, ``sign_file``, ``verify_self``,
            ``create_agreement``, ``sign_agreement``,
            ``check_agreement``, ``audit``, ``agent_info``,
            ``share_public_key``, ``share_agent``.

    Returns:
        The mcp_server instance (for chaining).

    Example::

        from fastmcp import FastMCP
        from jacs.adapters.mcp import register_jacs_tools

        mcp = FastMCP("jacs-server")
        register_jacs_tools(mcp)
        mcp.run()
    """
    adapter = BaseJacsAdapter(client=client, config_path=config_path, strict=strict)
    cl = adapter.client

    factories = {
        "sign_document": _make_sign_document,
        "verify_document": _make_verify_document,
        "sign_file": _make_sign_file,
        "verify_self": _make_verify_self,
        "create_agreement": _make_create_agreement,
        "sign_agreement": _make_sign_agreement,
        "check_agreement": _make_check_agreement,
        "audit": _make_audit,
        "agent_info": _make_agent_info,
        "share_public_key": _make_share_public_key,
        "share_agent": _make_share_agent,
    }

    names_to_register = list(factories.keys()) if tools is None else tools

    if tools is not None:
        unknown = set(tools) - set(factories)
        if unknown:
            raise ValueError(f"Unknown tool names: {unknown}. Valid: {sorted(factories)}")

    for name in names_to_register:
        factories[name](mcp_server, cl)

    return mcp_server


def _err(msg: str) -> str:
    return json.dumps({"success": False, "error": msg})


def _make_sign_document(mcp, cl):
    @mcp.tool(
        name="jacs_sign_document",
        description="Sign arbitrary JSON content to create a signed JACS document for attestation.",
    )
    def jacs_sign_document(content: str) -> str:
        """Sign JSON content. Pass a JSON string; returns signed JACS document."""
        try:
            data = json.loads(content) if isinstance(content, str) else content
            signed = cl.sign_message(data)
            return signed.raw
        except Exception as e:
            logger.warning("jacs_sign_document failed: %s", e)
            return _err(str(e))

    return jacs_sign_document


def _make_verify_document(mcp, cl):
    @mcp.tool(
        name="jacs_verify_document",
        description="Verify a signed JACS document's hash and cryptographic signature.",
    )
    def jacs_verify_document(signed_json: str) -> str:
        """Verify a signed JACS document. Returns verification result as JSON."""
        try:
            result = cl.verify(signed_json)
            return json.dumps({
                "success": True,
                "valid": result.valid,
                "signer_id": result.signer_id,
                "errors": result.errors,
            })
        except Exception as e:
            logger.warning("jacs_verify_document failed: %s", e)
            return _err(str(e))

    return jacs_verify_document


def _make_sign_file(mcp, cl):
    @mcp.tool(
        name="jacs_sign_file",
        description="Sign a file to create a signed JACS document. Supports reference and embed modes.",
    )
    def jacs_sign_file(file_path: str, embed: bool = False) -> str:
        """Sign a file. Returns signed JACS document."""
        try:
            _validate_mcp_file_path(file_path)
            signed = cl.sign_file(file_path, embed=embed)
            return signed.raw
        except Exception as e:
            logger.warning("jacs_sign_file failed: %s", e)
            return _err(str(e))

    return jacs_sign_file


def _make_verify_self(mcp, cl):
    @mcp.tool(
        name="jacs_verify_self",
        description="Verify the local agent's integrity and cryptographic signature.",
    )
    def jacs_verify_self() -> str:
        """Verify this agent's own integrity."""
        try:
            result = cl.verify_self()
            return json.dumps({
                "success": True,
                "valid": result.valid,
                "agent_id": cl.agent_id,
                "errors": result.errors,
            })
        except Exception as e:
            logger.warning("jacs_verify_self failed: %s", e)
            return _err(str(e))

    return jacs_verify_self


def _make_create_agreement(mcp, cl):
    @mcp.tool(
        name="jacs_create_agreement",
        description=(
            "Create a multi-party cryptographic agreement. "
            "Specify which agents must sign, an optional question, timeout, and quorum."
        ),
    )
    def jacs_create_agreement(
        document: str,
        agent_ids: str,
        question: str = "Do you agree?",
        timeout: Optional[str] = None,
        quorum: Optional[int] = None,
    ) -> str:
        """Create an agreement. document and agent_ids are JSON strings."""
        try:
            doc = json.loads(document) if isinstance(document, str) else document
            ids = json.loads(agent_ids) if isinstance(agent_ids, str) else agent_ids
            kwargs: dict = {"document": doc, "agent_ids": ids, "question": question}
            if timeout:
                kwargs["timeout"] = timeout
            if quorum:
                kwargs["quorum"] = quorum
            signed = cl.create_agreement(**kwargs)
            return signed.raw
        except Exception as e:
            logger.warning("jacs_create_agreement failed: %s", e)
            return _err(str(e))

    return jacs_create_agreement


def _make_sign_agreement(mcp, cl):
    @mcp.tool(
        name="jacs_sign_agreement",
        description="Co-sign an existing agreement. Adds your agent's cryptographic signature.",
    )
    def jacs_sign_agreement(agreement_json: str) -> str:
        """Sign an agreement. Pass the full agreement JSON."""
        try:
            signed = cl.sign_agreement(agreement_json)
            return signed.raw
        except Exception as e:
            logger.warning("jacs_sign_agreement failed: %s", e)
            return _err(str(e))

    return jacs_sign_agreement


def _make_check_agreement(mcp, cl):
    @mcp.tool(
        name="jacs_check_agreement",
        description=(
            "Check agreement status: who has signed, whether quorum is met, "
            "and if the agreement has expired."
        ),
    )
    def jacs_check_agreement(agreement_json: str) -> str:
        """Check agreement status. Returns status as JSON."""
        try:
            status = cl.check_agreement(agreement_json)
            # Serialize signers — they may be SignerStatus dataclasses
            signers = []
            for s in status.signers:
                if hasattr(s, "__dict__"):
                    signers.append(vars(s))
                else:
                    signers.append(s)
            return json.dumps({
                "success": True,
                "complete": status.complete,
                "signers": signers,
                "pending": status.pending,
            })
        except Exception as e:
            logger.warning("jacs_check_agreement failed: %s", e)
            return _err(str(e))

    return jacs_check_agreement


def _make_audit(mcp, cl):
    @mcp.tool(
        name="jacs_audit",
        description="Run a read-only JACS security audit and health checks.",
    )
    def jacs_audit() -> str:
        """Run a security audit. Returns JSON with risks and health checks."""
        try:
            result = cl.audit()
            return json.dumps(result) if isinstance(result, dict) else str(result)
        except Exception as e:
            logger.warning("jacs_audit failed: %s", e)
            return _err(str(e))

    return jacs_audit


def _make_agent_info(mcp, cl):
    @mcp.tool(
        name="jacs_agent_info",
        description="Get information about the current JACS agent (ID, name, public key).",
    )
    def jacs_agent_info() -> str:
        """Get agent information."""
        try:
            agent_json = cl.export_agent()
            parsed = json.loads(agent_json)
            public_key_pem = ""
            try:
                public_key_pem = (
                    cl.share_public_key()
                    if hasattr(cl, "share_public_key")
                    else cl.get_public_key()
                )
            except Exception:
                public_key_pem = ""
            return json.dumps({
                "success": True,
                "agent_id": cl.agent_id,
                "name": cl.name,
                "agent_document": parsed,
                "public_key_pem": public_key_pem,
            })
        except Exception as e:
            logger.warning("jacs_agent_info failed: %s", e)
            return _err(str(e))

    return jacs_agent_info


def _make_share_public_key(mcp, cl):
    @mcp.tool(
        name="jacs_share_public_key",
        description="Share this agent public key PEM for trust bootstrap and signature verification.",
    )
    def jacs_share_public_key() -> str:
        try:
            public_key_pem = cl.share_public_key() if hasattr(cl, "share_public_key") else cl.get_public_key()
            return json.dumps({"success": True, "public_key_pem": public_key_pem})
        except Exception as e:
            logger.warning("jacs_share_public_key failed: %s", e)
            return _err(str(e))

    return jacs_share_public_key


def _make_share_agent(mcp, cl):
    @mcp.tool(
        name="jacs_share_agent",
        description="Share this agent self-signed JACS document for trust establishment.",
    )
    def jacs_share_agent() -> str:
        try:
            agent_json = cl.share_agent() if hasattr(cl, "share_agent") else cl.export_agent()
            parsed = json.loads(agent_json)
            return json.dumps({"success": True, "agent_json": parsed})
        except Exception as e:
            logger.warning("jacs_share_agent failed: %s", e)
            return _err(str(e))

    return jacs_share_agent


# ---------------------------------------------------------------------------
# A2A tool registration
# ---------------------------------------------------------------------------


def register_a2a_tools(
    mcp_server: Any,
    client: Optional[Any] = None,
    config_path: Optional[str] = None,
    strict: bool = False,
) -> Any:
    """Register A2A protocol tools on a FastMCP server.

    Tools registered:
        - ``jacs_get_agent_card`` — Export this agent's A2A Agent Card.
        - ``jacs_sign_artifact`` — Wrap an A2A artifact with JACS provenance.
        - ``jacs_verify_a2a_artifact`` — Verify a JACS-wrapped A2A artifact.
        - ``jacs_assess_remote_agent`` — Assess trust for a remote Agent Card.

    Args:
        mcp_server: A FastMCP server instance.
        client: An existing JacsClient. If None, one is created via quickstart.
        config_path: Path to jacs.config.json (used if no client).
        strict: Raise on failures instead of returning error JSON.

    Returns:
        The mcp_server instance (for chaining).
    """
    adapter = BaseJacsAdapter(client=client, config_path=config_path, strict=strict)
    cl = adapter.client

    @mcp_server.tool(
        name="jacs_get_agent_card",
        description="Export this agent's A2A Agent Card for discovery.",
    )
    def jacs_get_agent_card(url: str = "", skills_json: str = "[]") -> str:
        """Export Agent Card. Optional url and skills_json (JSON array of service dicts)."""
        try:
            skills = json.loads(skills_json) if skills_json and skills_json != "[]" else None
            card = adapter.export_agent_card(
                url=url or None,
                skills=skills,
            )
            return json.dumps({"success": True, "agent_card": card})
        except Exception as e:
            logger.warning("jacs_get_agent_card failed: %s", e)
            return _err(str(e))

    @mcp_server.tool(
        name="jacs_sign_artifact",
        description="Wrap an A2A artifact with JACS provenance signature.",
    )
    def jacs_sign_artifact(artifact_json: str, artifact_type: str = "message") -> str:
        """Sign an A2A artifact. artifact_json is a JSON string."""
        try:
            artifact = json.loads(artifact_json)
            signed = cl.sign_artifact(artifact, artifact_type)
            return json.dumps({"success": True, "signed_artifact": signed})
        except Exception as e:
            logger.warning("jacs_sign_artifact failed: %s", e)
            return _err(str(e))

    @mcp_server.tool(
        name="jacs_verify_a2a_artifact",
        description="Verify a JACS-wrapped A2A artifact's provenance signature.",
    )
    def jacs_verify_a2a_artifact(wrapped_artifact_json: str) -> str:
        """Verify a wrapped A2A artifact. Returns verification result as JSON."""
        try:
            from ..a2a import JACSA2AIntegration

            wrapped = json.loads(wrapped_artifact_json)
            integration = JACSA2AIntegration(cl)
            result = integration.verify_wrapped_artifact(wrapped)
            return json.dumps({"success": True, **result})
        except Exception as e:
            logger.warning("jacs_verify_a2a_artifact failed: %s", e)
            return _err(str(e))

    @mcp_server.tool(
        name="jacs_assess_remote_agent",
        description=(
            "Assess trust for a remote A2A agent card. "
            "Policies: 'open' (accept all), 'verified' (require JACS extension), "
            "'strict' (require trust store entry)."
        ),
    )
    def jacs_assess_remote_agent(agent_card_json: str, policy: str = "verified") -> str:
        """Assess trust for a remote agent card JSON string."""
        try:
            result = adapter.assess_trust(agent_card_json, policy=policy)
            return json.dumps({
                "success": True,
                "jacs_registered": result["jacs_registered"],
                "trust_level": result["trust_level"],
                "allowed": result["allowed"],
            })
        except Exception as e:
            logger.warning("jacs_assess_remote_agent failed: %s", e)
            return _err(str(e))

    return mcp_server


# ---------------------------------------------------------------------------
# Trust store tool registration
# ---------------------------------------------------------------------------


def register_trust_tools(
    mcp_server: Any,
    client: Optional[Any] = None,
    config_path: Optional[str] = None,
    strict: bool = False,
) -> Any:
    """Register trust store tools on a FastMCP server.

    Tools registered:
        - ``jacs_trust_agent`` — Add an agent to the trust store.
        - ``jacs_trust_agent_with_key`` — Add an agent with explicit public key verification.
        - ``jacs_untrust_agent`` — Remove an agent from the trust store.
        - ``jacs_list_trusted`` — List all trusted agent IDs.
        - ``jacs_is_trusted`` — Check if a specific agent is trusted.

    Args:
        mcp_server: A FastMCP server instance.
        client: An existing JacsClient. If None, one is created via quickstart.
        config_path: Path to jacs.config.json (used if no client).
        strict: Raise on failures instead of returning error JSON.

    Returns:
        The mcp_server instance (for chaining).
    """
    adapter = BaseJacsAdapter(client=client, config_path=config_path, strict=strict)
    cl = adapter.client

    @mcp_server.tool(
        name="jacs_trust_agent",
        description="Add an agent to the local trust store by providing its agent JSON document.",
    )
    def jacs_trust_agent(agent_json: str) -> str:
        """Trust an agent. Pass the full agent JSON document."""
        try:
            result = cl.trust_agent(agent_json)
            return json.dumps({"success": True, "result": result})
        except Exception as e:
            logger.warning("jacs_trust_agent failed: %s", e)
            return _err(str(e))

    @mcp_server.tool(
        name="jacs_trust_agent_with_key",
        description=(
            "Add an agent to the trust store by verifying its document with an explicit public key PEM."
        ),
    )
    def jacs_trust_agent_with_key(agent_json: str, public_key_pem: str) -> str:
        try:
            if hasattr(cl, "trust_agent_with_key"):
                result = cl.trust_agent_with_key(agent_json, public_key_pem)
            else:
                raise RuntimeError("trust_agent_with_key is unavailable on this client")
            return json.dumps({"success": True, "result": result})
        except Exception as e:
            logger.warning("jacs_trust_agent_with_key failed: %s", e)
            return _err(str(e))

    @mcp_server.tool(
        name="jacs_untrust_agent",
        description="Remove an agent from the local trust store by agent ID. Requires JACS_MCP_ALLOW_UNTRUST=true.",
    )
    def jacs_untrust_agent(agent_id: str) -> str:
        """Untrust an agent by ID."""
        if not _is_untrust_allowed():
            return json.dumps({
                "success": False,
                "agent_id": agent_id,
                "error": "UNTRUST_DISABLED",
                "message": (
                    "Untrusting is disabled for security. "
                    "To enable, set JACS_MCP_ALLOW_UNTRUST=true environment variable "
                    "when starting the MCP server."
                ),
            })
        try:
            cl.untrust_agent(agent_id)
            return json.dumps({"success": True, "agent_id": agent_id})
        except Exception as e:
            logger.warning("jacs_untrust_agent failed: %s", e)
            return _err(str(e))

    @mcp_server.tool(
        name="jacs_list_trusted",
        description="List all agent IDs in the local trust store.",
    )
    def jacs_list_trusted() -> str:
        """List trusted agents."""
        try:
            agents = cl.list_trusted_agents()
            return json.dumps({"success": True, "trusted_agents": agents})
        except Exception as e:
            logger.warning("jacs_list_trusted failed: %s", e)
            return _err(str(e))

    @mcp_server.tool(
        name="jacs_is_trusted",
        description="Check whether a specific agent ID is in the local trust store.",
    )
    def jacs_is_trusted(agent_id: str) -> str:
        """Check trust status for an agent ID."""
        try:
            trusted = cl.is_trusted(agent_id)
            return json.dumps({"success": True, "agent_id": agent_id, "trusted": trusted})
        except Exception as e:
            logger.warning("jacs_is_trusted failed: %s", e)
            return _err(str(e))

    return mcp_server


# ---------------------------------------------------------------------------
# MCP-level middleware (FastMCP 2.9+ Middleware subclass)
# ---------------------------------------------------------------------------


class JacsMCPMiddleware:
    """FastMCP Middleware subclass that signs tool outputs and verifies inputs.

    This operates at the MCP protocol level (not HTTP), making it
    transport-agnostic (works with stdio, SSE, and Streamable HTTP).

    Requires fastmcp>=2.9.

    Usage::

        from fastmcp import FastMCP
        from jacs.adapters.mcp import JacsMCPMiddleware

        mcp = FastMCP("my-server")
        mcp.add_middleware(JacsMCPMiddleware())
        mcp.run()
    """

    def __init__(
        self,
        client: Optional[Any] = None,
        config_path: Optional[str] = None,
        strict: bool = False,
        sign_tool_results: bool = True,
        verify_tool_inputs: bool = False,
        a2a: bool = False,
    ) -> None:
        self._adapter = BaseJacsAdapter(
            client=client, config_path=config_path, strict=strict
        )
        self._sign = sign_tool_results
        self._verify = verify_tool_inputs
        self._strict = strict
        self._a2a = a2a

    def register_tools(self, mcp_server: Any) -> Any:
        """Register A2A and trust tools on a FastMCP server.

        Only registers tools if ``a2a=True`` was passed at init.
        Call this after constructing the middleware to add A2A tools
        to the same server::

            mw = JacsMCPMiddleware(client=client, a2a=True)
            mw.register_tools(mcp)
            mcp.add_middleware(mw)

        Returns:
            The mcp_server instance (for chaining).
        """
        if self._a2a:
            cl = self._adapter.client
            register_a2a_tools(mcp_server, client=cl, strict=self._strict)
            register_trust_tools(mcp_server, client=cl, strict=self._strict)
        return mcp_server

    async def on_call_tool(self, context, call_next):
        """Intercept tool calls: optionally verify input, sign output."""
        # Verify input arguments if enabled
        if self._verify and hasattr(context, "arguments"):
            for key, val in (context.arguments or {}).items():
                if isinstance(val, str) and '"jacsSignature"' in val:
                    try:
                        self._adapter.verify_input(val)
                    except Exception as e:
                        if self._strict:
                            raise
                        logger.warning("JACS input verification failed for %s: %s", key, e)

        result = await call_next(context)

        # Sign tool result
        if self._sign and result is not None:
            try:
                result_str = result if isinstance(result, str) else json.dumps(result)
                signed = self._adapter.sign_output(result_str)
                return signed
            except Exception as e:
                if self._strict:
                    raise
                logger.warning("JACS tool result signing failed: %s", e)

        return result


__all__ = [
    "register_jacs_tools",
    "register_a2a_tools",
    "register_trust_tools",
    "JacsMCPMiddleware",
]
