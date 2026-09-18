"""JACS MCP adapter — expose partial JACS operations as FastMCP tools.

The canonical full JACS MCP server is the Rust ``jacs-mcp`` crate and binary.
This module keeps Python-native middleware and adapter ergonomics, plus a
partial MCP compatibility layer for FastMCP servers.

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

Requires: pip install jacs[mcp]   (fastmcp>=3.2)
"""

import json
import logging
import os
from typing import Any, List, Optional

from .base import BaseJacsAdapter
from .._signed_document import require_portable_v2_signed_raw

logger = logging.getLogger("jacs.adapters.mcp")


def _is_untrust_allowed() -> bool:
    """Check if untrusting agents is allowed via environment variable.

    Mirrors the Rust MCP server's ``is_untrust_allowed()`` check.
    Untrusting requires explicit opt-in to prevent prompt injection
    attacks from removing trusted agents without user consent.
    """
    return os.environ.get("JACS_MCP_ALLOW_UNTRUST", "").lower() in ("true", "1")


def _validate_mcp_file_path(file_path: str, kind: str = "input") -> None:
    """Validate that a file path is safe for MCP tool use.

    Delegates to the Rust ``jacs_mcp_resolve_input_path`` PyO3 export so that
    Python enforcement matches Rust byte-for-byte (PRD §4.2.6, Issue 022).
    The Rust helper enforces the full six-layer policy: base-directory
    confinement, absolute-path rejection, traversal rejection, NUL byte
    rejection, symlink rejection, and (for ``kind='output'``) the
    overwrite-policy gate via ``JACS_MCP_OVERWRITE_OK``.

    Args:
        file_path: caller-supplied path.
        kind: ``"input"`` (default) or ``"output"``. ``"output"`` triggers
            the overwrite-policy gate.

    Raises:
        ValueError: If the path is unsafe per the Rust path policy.
    """
    if not file_path:
        raise ValueError("file_path cannot be empty")

    # Lazy import so adapters that never touch MCP don't pay the import cost.
    try:
        from jacs.jacs import jacs_mcp_resolve_input_path
    except ImportError as e:  # pragma: no cover — should never happen at runtime
        raise ValueError(
            f"Rust path policy delegate unavailable; rebuild jacspy: {e}"
        ) from e

    try:
        jacs_mcp_resolve_input_path(file_path, kind)
    except ValueError:
        raise


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
            ``check_agreement``, ``agent_info``,
            ``share_public_key``, ``share_agent``, ``sign_text``,
            ``verify_text``, ``sign_image``, ``verify_image``,
            ``extract_media_signature``.

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
        "agent_info": _make_agent_info,
        "share_public_key": _make_share_public_key,
        "share_agent": _make_share_agent,
        # Issue 005 / PRD §3 Q6 day-one parity contract for inline-text + media tools.
        "sign_text": _make_sign_text,
        "verify_text": _make_verify_text,
        "sign_image": _make_sign_image,
        "verify_image": _make_verify_image,
        "extract_media_signature": _make_extract_media_signature,
    }

    names_to_register = list(factories.keys()) if tools is None else tools

    if tools is not None:
        unknown = set(tools) - set(factories)
        if unknown:
            raise ValueError(
                f"Unknown tool names: {unknown}. Valid: {sorted(factories)}"
            )

    for name in names_to_register:
        factories[name](mcp_server, cl, strict=adapter.strict)

    return mcp_server


def _err(
    msg: str,
    *,
    strict: bool = False,
    exception: Optional[Exception] = None,
    **details: Any,
) -> str:
    """Apply one consistent MCP tool exception policy.

    Tool factories use this helper so ``strict=True`` cannot be accidentally
    ignored by one operation while another raises. Compatibility mode returns
    the existing structured error JSON; strict mode preserves the original
    exception type.
    """
    if strict:
        if exception is not None:
            raise exception
        raise RuntimeError(msg)
    return json.dumps({"success": False, **details, "error": msg})


def _make_sign_document(mcp, cl, *, strict=False):
    @mcp.tool(
        name="jacs_sign_document",
        description="Sign arbitrary JSON content to create a signed JACS document for attestation.",
    )
    def jacs_sign_document(content: str) -> str:
        """Sign JSON content. Pass a JSON string; returns signed JACS document."""
        try:
            data = json.loads(content) if isinstance(content, str) else content
            signed = cl.sign_message(data)
            return require_portable_v2_signed_raw(
                signed.raw,
                context="jacs_sign_document",
            )
        except Exception as e:
            logger.warning("jacs_sign_document failed: %s", e)
            return _err(str(e), strict=strict, exception=e)

    return jacs_sign_document


def _make_verify_document(mcp, cl, *, strict=False):
    @mcp.tool(
        name="jacs_verify_document",
        description="Verify a signed JACS document's hash and cryptographic signature.",
    )
    def jacs_verify_document(signed_json: str) -> str:
        """Verify a signed JACS document. Returns verification result as JSON."""
        try:
            result = cl.verify(signed_json)
            return json.dumps(
                {
                    "success": True,
                    "valid": result.valid,
                    "signer_id": result.signer_id,
                    "errors": result.errors,
                }
            )
        except Exception as e:
            logger.warning("jacs_verify_document failed: %s", e)
            return _err(str(e), strict=strict, exception=e)

    return jacs_verify_document


def _make_sign_file(mcp, cl, *, strict=False):
    @mcp.tool(
        name="jacs_sign_file",
        description="Sign a file to create a signed JACS document. Supports reference and embed modes.",
    )
    def jacs_sign_file(file_path: str, embed: bool = False) -> str:
        """Sign a file. Returns signed JACS document."""
        try:
            _validate_mcp_file_path(file_path)
            signed = cl.sign_file(file_path, embed=embed)
            return require_portable_v2_signed_raw(
                signed.raw,
                context="jacs_sign_file",
            )
        except Exception as e:
            logger.warning("jacs_sign_file failed: %s", e)
            return _err(str(e), strict=strict, exception=e)

    return jacs_sign_file


def _make_verify_self(mcp, cl, *, strict=False):
    @mcp.tool(
        name="jacs_verify_self",
        description="Verify the local agent's integrity and cryptographic signature.",
    )
    def jacs_verify_self() -> str:
        """Verify this agent's own integrity."""
        try:
            result = cl.verify_self()
            return json.dumps(
                {
                    "success": True,
                    "valid": result.valid,
                    "agent_id": cl.agent_id,
                    "errors": result.errors,
                }
            )
        except Exception as e:
            logger.warning("jacs_verify_self failed: %s", e)
            return _err(str(e), strict=strict, exception=e)

    return jacs_verify_self


def _make_create_agreement(mcp, cl, *, strict=False):
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
            return require_portable_v2_signed_raw(
                signed.raw,
                context="jacs_create_agreement",
            )
        except Exception as e:
            logger.warning("jacs_create_agreement failed: %s", e)
            return _err(str(e), strict=strict, exception=e)

    return jacs_create_agreement


def _make_sign_agreement(mcp, cl, *, strict=False):
    @mcp.tool(
        name="jacs_sign_agreement",
        description="Co-sign an existing agreement. Adds your agent's cryptographic signature.",
    )
    def jacs_sign_agreement(agreement_json: str) -> str:
        """Sign an agreement. Pass the full agreement JSON."""
        try:
            signed = cl.sign_agreement(agreement_json)
            return require_portable_v2_signed_raw(
                signed.raw,
                context="jacs_sign_agreement",
            )
        except Exception as e:
            logger.warning("jacs_sign_agreement failed: %s", e)
            return _err(str(e), strict=strict, exception=e)

    return jacs_sign_agreement


def _make_check_agreement(mcp, cl, *, strict=False):
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
            return json.dumps(
                {
                    "success": True,
                    "complete": status.complete,
                    "signers": signers,
                    "pending": status.pending,
                }
            )
        except Exception as e:
            logger.warning("jacs_check_agreement failed: %s", e)
            return _err(str(e), strict=strict, exception=e)

    return jacs_check_agreement


def _make_agent_info(mcp, cl, *, strict=False):
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
            return json.dumps(
                {
                    "success": True,
                    "agent_id": cl.agent_id,
                    "name": cl.name,
                    "agent_document": parsed,
                    "public_key_pem": public_key_pem,
                }
            )
        except Exception as e:
            logger.warning("jacs_agent_info failed: %s", e)
            return _err(str(e), strict=strict, exception=e)

    return jacs_agent_info


def _make_share_public_key(mcp, cl, *, strict=False):
    @mcp.tool(
        name="jacs_share_public_key",
        description="Share this agent public key PEM for trust bootstrap and signature verification.",
    )
    def jacs_share_public_key() -> str:
        try:
            public_key_pem = (
                cl.share_public_key()
                if hasattr(cl, "share_public_key")
                else cl.get_public_key()
            )
            return json.dumps({"success": True, "public_key_pem": public_key_pem})
        except Exception as e:
            logger.warning("jacs_share_public_key failed: %s", e)
            return _err(str(e), strict=strict, exception=e)

    return jacs_share_public_key


def _make_share_agent(mcp, cl, *, strict=False):
    @mcp.tool(
        name="jacs_export_agent",
        description="Export this agent's self-signed JACS document.",
    )
    @mcp.tool(
        name="jacs_share_agent",
        description="Legacy compatibility alias for jacs_export_agent.",
    )
    def jacs_export_agent() -> str:
        try:
            agent_json = (
                cl.share_agent() if hasattr(cl, "share_agent") else cl.export_agent()
            )
            parsed = json.loads(agent_json)
            return json.dumps({"success": True, "agent_json": parsed})
        except Exception as e:
            logger.warning("jacs_export_agent failed: %s", e)
            return _err(str(e), strict=strict, exception=e)

    return jacs_export_agent


# ---------------------------------------------------------------------------
# Issue 005 / PRD §3 — Inline text + media MCP tools (day-one parity).
#
# Mirrors the 5 Rust MCP tools registered in `jacs-mcp/src/jacs_tools.rs`.
# Path-validation reuses the local `_validate_mcp_file_path` until the
# Issue 001 PathPolicy delegate lands; tools surface the same JSON shape as
# their Rust counterparts so the `jacs-mcp-contract.json` snapshot covers all
# three runtimes.
# ---------------------------------------------------------------------------


def _make_sign_text(mcp, cl, *, strict=False):
    @mcp.tool(
        name="jacs_sign_text",
        description="Sign a text/markdown file in place with an inline JACS signature block.",
    )
    def jacs_sign_text(file_path: str, no_backup: bool = False) -> str:
        try:
            _validate_mcp_file_path(file_path)
            outcome = cl.sign_text(file_path, backup=not no_backup)
            return json.dumps(
                {
                    "success": True,
                    "file_path": getattr(outcome, "path", file_path),
                    "signers_added": getattr(outcome, "signers_added", 1),
                    "backup_path": getattr(outcome, "backup_path", None),
                }
            )
        except Exception as e:
            logger.warning("jacs_sign_text failed: %s", e)
            return _err(
                str(e),
                strict=strict,
                exception=e,
                file_path=file_path,
            )

    return jacs_sign_text


def _make_verify_text(mcp, cl, *, strict=False):
    @mcp.tool(
        name="jacs_verify_text",
        description=(
            "Verify inline JACS signatures in a text/markdown file. "
            "Permissive by default; strict=True turns missing-signature into an error."
        ),
    )
    def jacs_verify_text(
        file_path: str,
        strict: bool = False,
        key_dir: Optional[str] = None,
    ) -> str:
        try:
            _validate_mcp_file_path(file_path)
            result = cl.verify_text(file_path, strict=strict, key_dir=key_dir)
            return json.dumps(
                {
                    "success": True,
                    "file_path": file_path,
                    "result": getattr(result, "status", str(result)),
                    "signatures": getattr(result, "signatures", []),
                },
                default=str,
            )
        except Exception as e:
            logger.warning("jacs_verify_text failed: %s", e)
            return _err(
                str(e),
                strict=strict,
                exception=e,
                file_path=file_path,
            )

    return jacs_verify_text


def _make_sign_image(mcp, cl, *, strict=False):
    @mcp.tool(
        name="jacs_sign_image",
        description=(
            "Sign a PNG/JPEG/WebP image by embedding a JACS signature in metadata. "
            "Optional robust=True adds LSB fallback (PNG/JPEG only)."
        ),
    )
    def jacs_sign_image(
        input_path: str,
        output_path: str,
        robust: bool = False,
        refuse_overwrite: bool = False,
    ) -> str:
        try:
            _validate_mcp_file_path(input_path, "input")
            _validate_mcp_file_path(output_path, "output")
            outcome = cl.sign_image(
                input_path,
                output_path,
                robust=robust,
                refuse_overwrite=refuse_overwrite,
            )
            return json.dumps(
                {
                    "success": True,
                    "out_path": getattr(outcome, "out_path", output_path),
                    "signer_id": getattr(outcome, "signer_id", ""),
                    "format": getattr(outcome, "format", ""),
                    "robust": getattr(outcome, "robust", robust),
                }
            )
        except Exception as e:
            logger.warning("jacs_sign_image failed: %s", e)
            return _err(
                str(e),
                strict=strict,
                exception=e,
                input_path=input_path,
            )

    return jacs_sign_image


def _make_verify_image(mcp, cl, *, strict=False):
    @mcp.tool(
        name="jacs_verify_image",
        description="Verify the JACS signature embedded in a PNG/JPEG/WebP image.",
    )
    def jacs_verify_image(
        file_path: str,
        strict: bool = False,
        key_dir: Optional[str] = None,
    ) -> str:
        try:
            _validate_mcp_file_path(file_path)
            result = cl.verify_image(file_path, strict=strict, key_dir=key_dir)
            return json.dumps(
                {
                    "success": True,
                    "file_path": file_path,
                    "status": getattr(result, "status", str(result)),
                    "signer_id": getattr(result, "signer_id", None),
                    "format": getattr(result, "format", None),
                },
                default=str,
            )
        except Exception as e:
            logger.warning("jacs_verify_image failed: %s", e)
            return _err(
                str(e),
                strict=strict,
                exception=e,
                file_path=file_path,
            )

    return jacs_verify_image


def _make_extract_media_signature(mcp, cl, *, strict=False):
    @mcp.tool(
        name="jacs_extract_media_signature",
        description=(
            "Extract the JACS signed-document JSON embedded in a PNG/JPEG/WebP image. "
            "Default returns decoded JSON; raw_payload=True returns the base64url wire form."
        ),
    )
    def jacs_extract_media_signature(file_path: str, raw_payload: bool = False) -> str:
        try:
            _validate_mcp_file_path(file_path)
            payload = cl.extract_media_signature(file_path, raw_payload=raw_payload)
            return json.dumps(
                {
                    "success": True,
                    "file_path": file_path,
                    "payload": payload,
                    "raw_payload": raw_payload,
                }
            )
        except Exception as e:
            logger.warning("jacs_extract_media_signature failed: %s", e)
            return _err(
                str(e),
                strict=strict,
                exception=e,
                file_path=file_path,
            )

    return jacs_extract_media_signature


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
        name="jacs_export_agent_card",
        description="Export this agent's A2A Agent Card for discovery.",
    )
    @mcp_server.tool(
        name="jacs_get_agent_card",
        description="Legacy compatibility alias for jacs_export_agent_card.",
    )
    def jacs_export_agent_card(url: str = "", skills_json: str = "[]") -> str:
        """Export Agent Card. Optional url and skills_json (JSON array of service dicts)."""
        try:
            skills = (
                json.loads(skills_json) if skills_json and skills_json != "[]" else None
            )
            card = adapter.export_agent_card(
                url=url or None,
                skills=skills,
            )
            return json.dumps({"success": True, "agent_card": card})
        except Exception as e:
            logger.warning("jacs_export_agent_card failed: %s", e)
            return _err(str(e), strict=adapter.strict, exception=e)

    @mcp_server.tool(
        name="jacs_wrap_a2a_artifact",
        description="Wrap an A2A artifact with JACS provenance signature.",
    )
    @mcp_server.tool(
        name="jacs_sign_artifact",
        description="Legacy compatibility alias for jacs_wrap_a2a_artifact.",
    )
    def jacs_wrap_a2a_artifact(
        artifact_json: str, artifact_type: str = "artifact"
    ) -> str:
        """Sign an A2A artifact. artifact_json is a JSON string."""
        try:
            artifact = json.loads(artifact_json)
            signed = cl.sign_artifact(artifact, artifact_type)
            return json.dumps({"success": True, "signed_artifact": signed})
        except Exception as e:
            logger.warning("jacs_wrap_a2a_artifact failed: %s", e)
            return _err(str(e), strict=adapter.strict, exception=e)

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
            return _err(str(e), strict=adapter.strict, exception=e)

    @mcp_server.tool(
        name="jacs_assess_a2a_agent",
        description=(
            "Assess trust for a remote A2A agent card. "
            "Policies: 'open' (no identity assurance), 'verified' (native JWS/JWKS "
            "verification plus durable TOFU pin), 'strict' (explicit native-root trust "
            "plus compatibility binding)."
        ),
    )
    @mcp_server.tool(
        name="jacs_assess_remote_agent",
        description=(
            "Legacy compatibility alias for jacs_assess_a2a_agent. "
            "Policies: 'open' (no identity assurance), 'verified' (native JWS/JWKS "
            "verification plus durable TOFU pin), 'strict' (explicit native-root trust "
            "plus compatibility binding)."
        ),
    )
    def jacs_assess_a2a_agent(agent_card_json: str, policy: str = "verified") -> str:
        """Assess trust for a remote agent card JSON string."""
        try:
            result = adapter.assess_trust(agent_card_json, policy=policy)
            return json.dumps(
                {
                    "success": True,
                    "jacs_registered": result["jacs_registered"],
                    "trust_level": result["trust_level"],
                    "allowed": result["allowed"],
                }
            )
        except Exception as e:
            logger.warning("jacs_assess_a2a_agent failed: %s", e)
            return _err(str(e), strict=adapter.strict, exception=e)

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
            return _err(str(e), strict=adapter.strict, exception=e)

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
            return _err(str(e), strict=adapter.strict, exception=e)

    @mcp_server.tool(
        name="jacs_untrust_agent",
        description="Remove an agent from the local trust store by agent ID. Requires JACS_MCP_ALLOW_UNTRUST=true.",
    )
    def jacs_untrust_agent(agent_id: str) -> str:
        """Untrust an agent by ID."""
        if not _is_untrust_allowed():
            return json.dumps(
                {
                    "success": False,
                    "agent_id": agent_id,
                    "error": "UNTRUST_DISABLED",
                    "message": (
                        "Untrusting is disabled for security. "
                        "To enable, set JACS_MCP_ALLOW_UNTRUST=true environment variable "
                        "when starting the MCP server."
                    ),
                }
            )
        try:
            cl.untrust_agent(agent_id)
            return json.dumps({"success": True, "agent_id": agent_id})
        except Exception as e:
            logger.warning("jacs_untrust_agent failed: %s", e)
            return _err(str(e), strict=adapter.strict, exception=e)

    @mcp_server.tool(
        name="jacs_list_trusted_agents",
        description="List all agent IDs in the local trust store.",
    )
    @mcp_server.tool(
        name="jacs_list_trusted",
        description="Legacy compatibility alias for jacs_list_trusted_agents.",
    )
    def jacs_list_trusted_agents() -> str:
        """List trusted agents."""
        try:
            agents = cl.list_trusted_agents()
            return json.dumps({"success": True, "trusted_agents": agents})
        except Exception as e:
            logger.warning("jacs_list_trusted_agents failed: %s", e)
            return _err(str(e), strict=adapter.strict, exception=e)

    @mcp_server.tool(
        name="jacs_get_trusted_agent",
        description="Retrieve a trusted agent document by agent ID.",
    )
    def jacs_get_trusted_agent(agent_id: str) -> str:
        """Get a trusted agent document."""
        try:
            agent_json = cl.get_trusted_agent(agent_id)
            parsed = json.loads(agent_json)
            return json.dumps(
                {"success": True, "agent_id": agent_id, "agent_json": parsed}
            )
        except Exception as e:
            logger.warning("jacs_get_trusted_agent failed: %s", e)
            return _err(str(e), strict=adapter.strict, exception=e)

    @mcp_server.tool(
        name="jacs_is_trusted",
        description="Check whether a specific agent ID is in the local trust store.",
    )
    def jacs_is_trusted(agent_id: str) -> str:
        """Check trust status for an agent ID."""
        try:
            trusted = cl.is_trusted(agent_id)
            return json.dumps(
                {"success": True, "agent_id": agent_id, "trusted": trusted}
            )
        except Exception as e:
            logger.warning("jacs_is_trusted failed: %s", e)
            return _err(str(e), strict=adapter.strict, exception=e)

    return mcp_server


# ---------------------------------------------------------------------------
# MCP-level middleware (FastMCP 3.2+ callable middleware)
# ---------------------------------------------------------------------------


def _jsonable_mcp_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(by_alias=True, mode="json", exclude_none=True)
    if isinstance(value, list):
        return [_jsonable_mcp_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _jsonable_mcp_value(item) for key, item in value.items()}
    return value


def _signed_argument_json(value: Any) -> Optional[str]:
    candidate = value
    if isinstance(value, str):
        try:
            candidate = json.loads(value)
        except json.JSONDecodeError:
            return None
    if not isinstance(candidate, dict) or not isinstance(
        candidate.get("jacsSignature"), dict
    ):
        return None
    return value if isinstance(value, str) else json.dumps(value)


class JacsMCPMiddleware:
    """FastMCP Middleware subclass that signs tool outputs and verifies inputs.

    This operates at the MCP protocol level (not HTTP), making it
    transport-agnostic (works with stdio, SSE, and Streamable HTTP).

    Requires fastmcp>=3.2.

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
        allow_unverified_passthrough: bool = False,
        allow_unsigned_output: bool = False,
        a2a: bool = False,
    ) -> None:
        """Configure middleware.

        When ``verify_tool_inputs`` is enabled, failed verification stops the
        tool call by default. ``allow_unverified_passthrough=True`` restores
        the legacy log-and-continue behavior and should not be used at trust
        boundaries. Signing failures also stop the call by default;
        ``allow_unsigned_output=True`` is the dangerous compatibility opt-in.
        """
        self._adapter = BaseJacsAdapter(
            client=client,
            config_path=config_path,
            strict=strict,
            allow_unverified_passthrough=allow_unverified_passthrough,
            allow_unsigned_output=allow_unsigned_output,
        )
        self._sign = sign_tool_results
        self._verify = verify_tool_inputs
        self._strict = strict
        self._allow_unverified_passthrough = self._adapter.allow_unverified_passthrough
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

    async def __call__(self, context, call_next):
        """FastMCP middleware entrypoint, kept optional-dependency safe."""
        if getattr(context, "method", None) == "tools/call":
            return await self.on_call_tool(context, call_next)
        return await call_next(context)

    async def on_call_tool(self, context, call_next):
        """Intercept tool calls: optionally verify input, sign output."""
        # Verify input arguments if enabled
        message = getattr(context, "message", None)
        arguments = getattr(message, "arguments", None)
        if arguments is None:
            arguments = getattr(context, "arguments", None)
        if self._verify and isinstance(arguments, dict):
            for key, val in list(arguments.items()):
                signed_json = _signed_argument_json(val)
                if signed_json is not None:
                    try:
                        arguments[key] = self._adapter.verify_input(signed_json)
                    except Exception as e:
                        logger.warning(
                            "JACS input verification failed for %s: %s", key, e
                        )
                        if not self._allow_unverified_passthrough:
                            raise

        result = await call_next(context)

        # Sign tool result
        if self._sign and result is not None:
            try:
                try:
                    from fastmcp.tools.tool import ToolResult
                except ImportError:  # pragma: no cover - optional dependency absent
                    ToolResult = None  # type: ignore[assignment, misc]

                try:
                    from mcp.types import CreateTaskResult
                except ImportError:  # pragma: no cover - older MCP SDK
                    CreateTaskResult = None  # type: ignore[assignment, misc]

                if CreateTaskResult is not None and isinstance(
                    result, CreateTaskResult
                ):
                    result_payload = _jsonable_mcp_value(result)
                    signed = self._adapter.sign_output(result_payload)
                    merged_meta = dict(result.meta or {})
                    merged_meta["jacsSignedDocument"] = json.loads(signed)
                    return result.model_copy(update={"meta": merged_meta})

                if ToolResult is not None and isinstance(result, ToolResult):
                    result_payload = {
                        "content": _jsonable_mcp_value(result.content),
                        "structuredContent": _jsonable_mcp_value(
                            result.structured_content
                        ),
                        "meta": _jsonable_mcp_value(result.meta),
                    }
                    signed = self._adapter.sign_output(result_payload)
                    merged_meta = dict(result.meta or {})
                    merged_meta["jacsSignedDocument"] = json.loads(signed)
                    return ToolResult(
                        content=result.content,
                        structured_content=result.structured_content,
                        meta=merged_meta,
                    )

                result_payload = result if isinstance(result, str) else result
                signed = self._adapter.sign_output(result_payload)
                return signed
            except Exception as e:
                logger.warning("JACS tool result signing failed: %s", e)
                if not self._adapter.allow_unsigned_output:
                    raise

        return result


__all__ = [
    "register_jacs_tools",
    "register_a2a_tools",
    "register_trust_tools",
    "JacsMCPMiddleware",
]
