"""Anthropic / Claude SDK adapter for JACS.

Provides two integration points:

1. ``signed_tool`` -- a decorator/wrapper for tool functions used with the
   base ``anthropic`` Python SDK.  It signs the tool's return value via JACS
   before the caller sends it back as a ``tool_result`` content block.

2. ``JacsToolHook`` -- a callable that implements the ``PostToolUse`` hook
   interface expected by the Claude Agent SDK.  It signs tool results
   automatically before they are returned to the model.

Neither ``anthropic`` nor ``claude-agent-sdk`` are required at import time;
all framework imports are lazy so this module works with just ``jacs``.

Example (base SDK)::

    from jacs.adapters.anthropic import signed_tool
    from jacs.client import JacsClient

    client = JacsClient.ephemeral()

    @signed_tool(client=client)
    def get_weather(location: str) -> str:
        return f"Weather in {location}: sunny"

    # result is now a signed JACS JSON string
    result = get_weather("Paris")

Example (Claude Agent SDK)::

    from jacs.adapters.anthropic import JacsToolHook
    from jacs.client import JacsClient

    hook = JacsToolHook(client=JacsClient.ephemeral())
    # Pass ``hook`` as a PostToolUse hook in ClaudeAgentOptions.
"""

import asyncio
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, Union, overload

from .base import BaseJacsAdapter

F = TypeVar("F", bound=Callable[..., Any])


# ------------------------------------------------------------------
# signed_tool -- decorator / wrapper for base Anthropic SDK tools
# ------------------------------------------------------------------


@overload
def signed_tool(func: F) -> F: ...


@overload
def signed_tool(
    func: None = ...,
    *,
    client: Any = ...,
    config_path: Optional[str] = ...,
    strict: bool = ...,
) -> Callable[[F], F]: ...


def signed_tool(
    func: Optional[Callable[..., Any]] = None,
    *,
    client: Any = None,
    config_path: Optional[str] = None,
    strict: bool = False,
) -> Union[Callable[..., Any], Callable[[Callable[..., Any]], Callable[..., Any]]]:
    """Wrap a tool function to auto-sign its return value with JACS.

    Can be used as a decorator with keyword arguments::

        @signed_tool(client=jacs_client)
        def my_tool(arg: str) -> str: ...

    Or as a direct wrapper::

        signed_my_tool = signed_tool(my_tool, client=jacs_client)

    The returned wrapper preserves sync/async nature of the original
    function.  The signed result is a JSON string containing the JACS
    document envelope with cryptographic signature.

    Args:
        func: The tool function to wrap (positional usage).
        client: A ``JacsClient`` instance.  If *None*, one is created
            via ``BaseJacsAdapter``'s default resolution.
        config_path: Optional config path forwarded to ``BaseJacsAdapter``.
        strict: If *True*, signing failures raise.  If *False* (default),
            the original return value is passed through.
    """
    adapter = BaseJacsAdapter(client=client, config_path=config_path, strict=strict)

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        if asyncio.iscoroutinefunction(fn):

            @wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> str:
                result = await fn(*args, **kwargs)
                return adapter.sign_output_or_passthrough(result)

            return async_wrapper

        @wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> str:
            result = fn(*args, **kwargs)
            return adapter.sign_output_or_passthrough(result)

        return sync_wrapper

    if func is not None:
        return decorator(func)
    return decorator


# ------------------------------------------------------------------
# JacsToolHook -- PostToolUse hook for the Claude Agent SDK
# ------------------------------------------------------------------


class JacsToolHook:
    """``PostToolUse`` hook for the Claude Agent SDK.

    Signs tool results before they are returned to the model, providing
    cryptographic provenance for every tool output.

    Usage::

        from jacs.adapters.anthropic import JacsToolHook
        from jacs.client import JacsClient

        hook = JacsToolHook(client=JacsClient.ephemeral())

        # In ClaudeAgentOptions:
        # hooks={"PostToolUse": [HookMatcher(hooks=[hook])]}

    Args:
        client: A ``JacsClient`` instance.
        config_path: Optional config path forwarded to ``BaseJacsAdapter``.
        strict: If *True*, signing failures raise.
    """

    def __init__(
        self,
        client: Any = None,
        config_path: Optional[str] = None,
        strict: bool = False,
    ) -> None:
        self._adapter = BaseJacsAdapter(
            client=client, config_path=config_path, strict=strict
        )

    @property
    def adapter(self) -> BaseJacsAdapter:
        """The underlying adapter instance."""
        return self._adapter

    async def __call__(
        self,
        input_data: dict,
        tool_use_id: Optional[str] = None,
        context: Any = None,
    ) -> dict:
        """Sign the tool response and return the hook output envelope.

        Args:
            input_data: Dict containing at least ``"tool_response"``
                with the raw tool output string.
            tool_use_id: Optional tool use identifier.
            context: Optional agent context (unused).

        Returns:
            A dict matching the Claude Agent SDK ``PostToolUse`` hook
            output schema.
        """
        tool_response = input_data.get("tool_response", "")
        signed = self._adapter.sign_output_or_passthrough(tool_response)
        return {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "toolResult": signed,
            }
        }


__all__ = ["signed_tool", "JacsToolHook"]
