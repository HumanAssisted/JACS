"""CrewAI adapter for JACS cryptographic signing and verification.

Provides guardrails, task decorators, and tool wrappers that integrate
JACS data provenance into CrewAI workflows.

All crewai imports are lazy so this module can be imported without
crewai installed -- actual usage will fail with a clear error.

Example:
    from jacs.adapters.crewai import jacs_guardrail, JacsSignedTool
    from jacs.client import JacsClient

    client = JacsClient.quickstart()

    # Task guardrail that signs every output
    task = Task(
        description="Summarize the report",
        agent=my_agent,
        guardrail=jacs_guardrail(client=client),
    )

    # Wrap an existing tool to auto-sign its output
    signed_search = JacsSignedTool(SearchTool(), client=client)
"""

import logging
from typing import Any, Callable, Optional, Tuple

from .base import BaseJacsAdapter

logger = logging.getLogger("jacs.adapters.crewai")


def _require_crewai(component: str = "crewai") -> None:
    """Raise ImportError with a helpful message if crewai is not installed."""
    try:
        import crewai  # noqa: F401
    except ImportError:
        raise ImportError(
            f"crewai is required for {component}. "
            "Install it with: pip install crewai"
        )


def jacs_guardrail(
    client: Optional[Any] = None,
    config_path: Optional[str] = None,
    strict: bool = False,
) -> Callable[[Any], Tuple[bool, Any]]:
    """Create a CrewAI task guardrail that signs task outputs with JACS.

    Returns a callable with the CrewAI guardrail signature:
    ``(TaskOutput) -> Tuple[bool, Any]``.

    In permissive mode (default), signing failures pass the original
    output through. In strict mode, failures reject the task output.

    Args:
        client: An existing JacsClient instance. If None, one is
            created from config_path or via quickstart.
        config_path: Path to jacs.config.json (used only if client
            is None).
        strict: If True, signing failures cause the guardrail to
            reject the output (return ``(False, error_msg)``).

    Returns:
        A guardrail function suitable for ``Task(guardrail=...)``.

    Example:
        task = Task(
            description="Analyze data",
            agent=analyst,
            guardrail=jacs_guardrail(client=jacs_client),
        )
    """
    adapter = BaseJacsAdapter(client=client, config_path=config_path, strict=strict)

    def guardrail(result: Any) -> Tuple[bool, Any]:
        raw = getattr(result, "raw", None)
        if raw is None:
            raw = str(result)
        data = raw if isinstance(raw, str) else str(raw)

        try:
            signed = adapter.sign_output(data)
            return (True, signed)
        except Exception as exc:
            if strict:
                return (False, f"JACS signing failed: {exc}")
            logger.warning("JACS guardrail signing failed (passthrough): %s", exc)
            return (True, data)

    return guardrail


def signed_task(
    client: Optional[Any] = None,
    config_path: Optional[str] = None,
    strict: bool = False,
    **task_kwargs: Any,
) -> Callable:
    """Decorator/factory that creates a CrewAI Task with a JACS guardrail.

    Can be used as a decorator on a function that returns Task kwargs,
    or called directly as a factory.

    Args:
        client: An existing JacsClient instance.
        config_path: Path to jacs.config.json.
        strict: Whether signing failures should reject the task.
        **task_kwargs: Additional keyword arguments forwarded to
            ``crewai.Task``.

    Returns:
        A decorator that wraps a function returning Task kwargs, or
        (when called with task_kwargs) a Task instance directly.

    Example as decorator::

        @signed_task(client=jacs_client)
        def analysis_task(analyst_agent):
            return dict(description="Analyze data", agent=analyst_agent)

        task = analysis_task(my_agent)

    Example as factory::

        task = signed_task(
            client=jacs_client,
            description="Analyze data",
            agent=my_agent,
        )
    """
    _require_crewai("signed_task")
    from crewai import Task

    guardrail_fn = jacs_guardrail(client=client, config_path=config_path, strict=strict)

    if task_kwargs:
        task_kwargs.setdefault("guardrail", guardrail_fn)
        return Task(**task_kwargs)

    def decorator(fn: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> "Task":
            result = fn(*args, **kwargs)
            if isinstance(result, dict):
                result.setdefault("guardrail", guardrail_fn)
                return Task(**result)
            # If the function already returns a Task, attach guardrail
            if isinstance(result, Task) and result.guardrail is None:
                result.guardrail = guardrail_fn
            return result
        wrapper.__name__ = getattr(fn, "__name__", "signed_task")
        wrapper.__doc__ = getattr(fn, "__doc__", None)
        return wrapper

    return decorator


class JacsSignedTool:
    """Wraps a CrewAI BaseTool to auto-sign its output with JACS.

    The wrapper preserves the inner tool's name, description, and
    schema so it appears identical to CrewAI's execution engine.

    Args:
        inner_tool: The CrewAI tool instance to wrap.
        client: An existing JacsClient instance.
        config_path: Path to jacs.config.json.
        strict: If True, signing failures raise. If False (default),
            the unsigned output is returned.

    Example:
        from crewai_tools import SerperDevTool
        signed_search = JacsSignedTool(SerperDevTool(), client=jacs_client)
    """

    def __init__(
        self,
        inner_tool: Any,
        client: Optional[Any] = None,
        config_path: Optional[str] = None,
        strict: bool = False,
    ) -> None:
        self._inner = inner_tool
        self._adapter = BaseJacsAdapter(
            client=client, config_path=config_path, strict=strict
        )
        # Mirror tool metadata for CrewAI discovery
        self.name = getattr(inner_tool, "name", "unknown_tool")
        self.description = getattr(inner_tool, "description", "")
        self.args_schema = getattr(inner_tool, "args_schema", None)

    @property
    def inner_tool(self) -> Any:
        """The wrapped inner tool."""
        return self._inner

    @property
    def adapter(self) -> BaseJacsAdapter:
        """The JACS adapter used for signing."""
        return self._adapter

    def _run(self, **kwargs: Any) -> str:
        """Execute the inner tool and sign the output."""
        result = self._inner._run(**kwargs)
        return self._adapter.sign_output_or_passthrough(result)


class JacsVerifiedInput:
    """Mixin or wrapper that verifies JACS-signed input before processing.

    Useful for tools that consume output from other signed tools.

    Args:
        inner_tool: The CrewAI tool instance to wrap.
        client: An existing JacsClient instance.
        config_path: Path to jacs.config.json.
        strict: If True, verification failures raise.
    """

    def __init__(
        self,
        inner_tool: Any,
        client: Optional[Any] = None,
        config_path: Optional[str] = None,
        strict: bool = False,
    ) -> None:
        self._inner = inner_tool
        self._adapter = BaseJacsAdapter(
            client=client, config_path=config_path, strict=strict
        )
        self.name = getattr(inner_tool, "name", "unknown_tool")
        self.description = getattr(inner_tool, "description", "")
        self.args_schema = getattr(inner_tool, "args_schema", None)

    @property
    def inner_tool(self) -> Any:
        return self._inner

    @property
    def adapter(self) -> BaseJacsAdapter:
        return self._adapter

    def _run(self, signed_input: str = "", **kwargs: Any) -> Any:
        """Verify input, then delegate to the inner tool."""
        payload = self._adapter.verify_input_or_passthrough(signed_input)
        if isinstance(payload, dict):
            kwargs.update(payload)
            return self._inner._run(**kwargs)
        kwargs["input"] = payload
        return self._inner._run(**kwargs)


__all__ = [
    "jacs_guardrail",
    "signed_task",
    "JacsSignedTool",
    "JacsVerifiedInput",
]
