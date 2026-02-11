"""LangChain and LangGraph adapter for JACS cryptographic signing.

Provides four integration points:

1. ``jacs_signing_middleware`` -- A ``@wrap_tool_call`` middleware for
   LangChain 1.0's ``create_agent(middleware=[...])``.  Signs every tool
   result before it is returned to the model.  This is the **preferred**
   approach for LangChain 1.0+ users.

2. ``JacsSigningMiddleware`` -- Class-based ``AgentMiddleware`` subclass
   with a ``wrap_tool_call`` method.  Use this when you need to combine
   JACS signing with other middleware hooks in a single class.

3. ``jacs_wrap_tool_call`` / ``jacs_awrap_tool_call`` -- Lower-level
   wrappers for LangGraph's ``ToolNode(wrap_tool_call=...)`` parameter.
   Use this for custom LangGraph workflows.

4. ``signed_tool`` -- Wraps any LangChain ``BaseTool`` so its output
   is auto-signed.  Works with ``langchain-core`` alone (no LangGraph).

5. ``with_jacs_signing`` -- Convenience that creates a LangGraph
   ``ToolNode`` with JACS signing already wired in.

All ``langchain``, ``langchain-core``, and ``langgraph`` imports are
lazy so this module can be imported without those packages installed.

Example (LangChain 1.0 middleware -- preferred)::

    from jacs.adapters.langchain import jacs_signing_middleware
    from langchain.agents import create_agent

    agent = create_agent(
        model="openai:gpt-4o",
        tools=[search, calculator],
        middleware=[jacs_signing_middleware(client=jacs_client)],
    )

Example (Class-based middleware)::

    from jacs.adapters.langchain import JacsSigningMiddleware

    middleware = JacsSigningMiddleware(client=jacs_client, strict=True)
    agent = create_agent(model=..., tools=..., middleware=[middleware])

Example (LangGraph ToolNode -- lower-level)::

    from langgraph.prebuilt import ToolNode
    from jacs.adapters.langchain import jacs_wrap_tool_call

    tool_node = ToolNode(
        tools=[my_tool],
        wrap_tool_call=jacs_wrap_tool_call(client=jacs_client),
    )

Example (LangChain BaseTool wrapper)::

    from jacs.adapters.langchain import signed_tool

    signed_search = signed_tool(search_tool, client=jacs_client)
    result = signed_search.invoke({"query": "hello"})  # auto-signed
"""

import logging
from typing import Any, Callable, List, Optional

from .base import BaseJacsAdapter

logger = logging.getLogger("jacs.adapters.langchain")


# ------------------------------------------------------------------
# LangChain 1.0 create_agent middleware (preferred)
# ------------------------------------------------------------------


def jacs_signing_middleware(
    client: Optional[Any] = None,
    config_path: Optional[str] = None,
    strict: bool = False,
) -> Any:
    """Create a ``@wrap_tool_call`` middleware for LangChain 1.0 agents.

    Returns a middleware object suitable for passing to
    ``create_agent(middleware=[...])``.  Signs every tool result with
    JACS before it is returned to the model.

    Requires ``langchain>=1.0.0``.

    Args:
        client: A ``JacsClient`` instance.  If *None*, one is created
            via ``BaseJacsAdapter``'s default resolution.
        config_path: Optional config path forwarded to ``BaseJacsAdapter``.
        strict: If *True*, signing failures raise.  If *False* (default),
            the original result is passed through.

    Returns:
        A middleware object created by the ``@wrap_tool_call`` decorator.
    """
    try:
        from langchain.agents.middleware import wrap_tool_call
    except ImportError:
        raise ImportError(
            "langchain>=1.0.0 is required for jacs_signing_middleware. "
            "Install it with: pip install 'langchain>=1.0.0'"
        )

    adapter = BaseJacsAdapter(client=client, config_path=config_path, strict=strict)

    @wrap_tool_call
    def jacs_signer(request: Any, handler: Callable) -> Any:
        result = handler(request)
        return _sign_tool_message(adapter, result, request)

    return jacs_signer


class JacsSigningMiddleware:
    """Class-based middleware that signs tool results with JACS.

    Implements the ``wrap_tool_call`` method expected by LangChain 1.0's
    ``AgentMiddleware`` protocol.  Use this when you want to combine
    JACS signing with other middleware hooks in a single class, or when
    you need to subclass for custom behavior.

    Usage::

        from jacs.adapters.langchain import JacsSigningMiddleware

        middleware = JacsSigningMiddleware(client=jacs_client)
        agent = create_agent(
            model="openai:gpt-4o",
            tools=tools,
            middleware=[middleware],
        )

    Args:
        client: A ``JacsClient`` instance.
        config_path: Optional config path.
        strict: If *True*, signing failures raise.
    """

    def __init__(
        self,
        client: Optional[Any] = None,
        config_path: Optional[str] = None,
        strict: bool = False,
    ) -> None:
        self._adapter = BaseJacsAdapter(
            client=client, config_path=config_path, strict=strict
        )

    @property
    def adapter(self) -> BaseJacsAdapter:
        """The underlying BaseJacsAdapter instance."""
        return self._adapter

    def wrap_tool_call(self, request: Any, handler: Callable) -> Any:
        """Intercept a tool call, execute it, and sign the result.

        This method matches the ``AgentMiddleware.wrap_tool_call``
        protocol expected by LangChain 1.0.

        Args:
            request: A ``ToolCallRequest`` with ``tool_call`` dict.
            handler: Callable that executes the tool.

        Returns:
            A ``ToolMessage`` with signed content.
        """
        result = handler(request)
        return _sign_tool_message(self._adapter, result, request)


# ------------------------------------------------------------------
# LangGraph ToolNode wrappers (lower-level)
# ------------------------------------------------------------------


def jacs_wrap_tool_call(
    client: Optional[Any] = None,
    config_path: Optional[str] = None,
    strict: bool = False,
) -> Callable:
    """Create a ``wrap_tool_call`` function for LangGraph ToolNode.

    The returned callable has signature
    ``(request, execute) -> ToolMessage`` matching what LangGraph
    ``ToolNode`` expects for its ``wrap_tool_call`` parameter.

    For LangChain 1.0 ``create_agent`` middleware, prefer
    :func:`jacs_signing_middleware` instead.

    Args:
        client: A ``JacsClient`` instance.  If *None*, one is created
            via ``BaseJacsAdapter``'s default resolution.
        config_path: Optional config path forwarded to ``BaseJacsAdapter``.
        strict: If *True*, signing failures raise.  If *False* (default),
            the original result is passed through.
    """
    adapter = BaseJacsAdapter(client=client, config_path=config_path, strict=strict)

    def wrapper(request: Any, execute: Callable) -> Any:
        result = execute(request)
        return _sign_tool_message(adapter, result)

    return wrapper


def jacs_awrap_tool_call(
    client: Optional[Any] = None,
    config_path: Optional[str] = None,
    strict: bool = False,
) -> Callable:
    """Async version of :func:`jacs_wrap_tool_call`.

    Returns an async callable with signature
    ``(request, execute) -> ToolMessage``.
    """
    adapter = BaseJacsAdapter(client=client, config_path=config_path, strict=strict)

    async def wrapper(request: Any, execute: Callable) -> Any:
        result = await execute(request)
        return _sign_tool_message(adapter, result)

    return wrapper


# ------------------------------------------------------------------
# Shared signing logic
# ------------------------------------------------------------------


def _sign_tool_message(
    adapter: BaseJacsAdapter,
    result: Any,
    request: Any = None,
) -> Any:
    """Sign the content of a ToolMessage-like object.

    If the result has a ``content`` attribute (like langchain_core
    ToolMessage), sign the content and return a new ToolMessage with the
    signed payload.  Otherwise return the result unchanged.

    Args:
        adapter: The BaseJacsAdapter to use for signing.
        result: The tool result (typically a ToolMessage).
        request: Optional ToolCallRequest for extracting tool_call_id
            when the result doesn't carry one.
    """
    if not hasattr(result, "content"):
        return result

    signed = adapter.sign_output_or_passthrough(result.content)

    # Extract tool_call_id from result or request
    tool_call_id = getattr(result, "tool_call_id", "")
    if not tool_call_id and request is not None:
        tool_call = getattr(request, "tool_call", None)
        if isinstance(tool_call, dict):
            tool_call_id = tool_call.get("id", "")

    try:
        from langchain_core.messages import ToolMessage
    except ImportError:
        # langchain-core not installed -- mutate in place as fallback
        result.content = signed
        if tool_call_id:
            result.tool_call_id = tool_call_id
        return result

    kwargs: dict[str, Any] = {
        "content": signed,
        "tool_call_id": tool_call_id,
    }
    name = getattr(result, "name", None)
    if name is not None:
        kwargs["name"] = name

    return ToolMessage(**kwargs)


# ------------------------------------------------------------------
# LangChain BaseTool wrapper
# ------------------------------------------------------------------


def signed_tool(
    tool: Any,
    client: Optional[Any] = None,
    config_path: Optional[str] = None,
    strict: bool = False,
) -> Any:
    """Wrap a LangChain BaseTool to auto-sign its output.

    Returns a new tool instance that delegates to *tool* and signs the
    result with JACS before returning it.

    Args:
        tool: A LangChain ``BaseTool`` instance.
        client: A ``JacsClient`` instance.
        config_path: Optional config path forwarded to ``BaseJacsAdapter``.
        strict: If *True*, signing failures raise.

    Returns:
        A new ``BaseTool`` (``StructuredTool``) that wraps *tool*.
    """
    try:
        from langchain_core.tools import StructuredTool
    except ImportError:
        raise ImportError(
            "langchain-core is required for signed_tool. "
            "Install it with: pip install langchain-core"
        )
    adapter = BaseJacsAdapter(client=client, config_path=config_path, strict=strict)

    original_name = getattr(tool, "name", "jacs_tool")
    original_desc = getattr(tool, "description", "")
    original_schema = getattr(tool, "args_schema", None)

    def _run_and_sign(**kwargs: Any) -> str:
        raw = tool.invoke(kwargs)
        return adapter.sign_output_or_passthrough(raw)

    wrapped = StructuredTool.from_function(
        func=_run_and_sign,
        name=original_name,
        description=original_desc,
        args_schema=original_schema,
    )
    # Stash a reference to the original tool for introspection
    wrapped._inner_tool = tool  # type: ignore[attr-defined]
    return wrapped


# ------------------------------------------------------------------
# Convenience: with_jacs_signing
# ------------------------------------------------------------------


def with_jacs_signing(
    tools: List[Any],
    client: Optional[Any] = None,
    config_path: Optional[str] = None,
    strict: bool = False,
) -> Any:
    """Create a LangGraph ToolNode with JACS signing pre-configured.

    Convenience wrapper that combines ``ToolNode`` construction with
    ``jacs_wrap_tool_call``.

    Args:
        tools: List of LangChain tools to include.
        client: A ``JacsClient`` instance.
        config_path: Optional config path.
        strict: If *True*, signing failures raise.

    Returns:
        A ``langgraph.prebuilt.ToolNode`` with ``wrap_tool_call`` set.
    """
    try:
        from langgraph.prebuilt import ToolNode
    except ImportError:
        raise ImportError(
            "langgraph is required for with_jacs_signing. "
            "Install it with: pip install langgraph"
        )

    return ToolNode(
        tools=tools,
        wrap_tool_call=jacs_wrap_tool_call(
            client=client, config_path=config_path, strict=strict
        ),
    )


__all__ = [
    "jacs_signing_middleware",
    "JacsSigningMiddleware",
    "jacs_wrap_tool_call",
    "jacs_awrap_tool_call",
    "signed_tool",
    "with_jacs_signing",
]
