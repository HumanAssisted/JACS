"""CrewAI adapter for JACS cryptographic signing and verification.

Provides guardrails, task decorators, and tool wrappers that integrate
JACS data provenance into CrewAI workflows.

All crewai imports are lazy so this module can be imported without
crewai installed -- actual usage will fail with a clear error.

Example:
    from jacs.adapters.crewai import jacs_guardrail, JacsSignedTool
    from jacs.client import JacsClient

    client = JacsClient.quickstart(name="crewai-agent", domain="crewai.local")

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
            f"crewai is required for {component}. Install it with: pip install crewai"
        )


def jacs_guardrail(
    client: Optional[Any] = None,
    config_path: Optional[str] = None,
    strict: bool = False,
    allow_unsigned_output: bool = False,
    allow_plain_signature_fallback: bool = False,
    attest: bool = False,
) -> Callable[[Any], Tuple[bool, Any]]:
    """Create a CrewAI task guardrail that signs task outputs with JACS.

    Returns a callable with the CrewAI guardrail signature:
    ``(TaskOutput) -> Tuple[bool, Any]``.

    Signing failures reject the task output by default. Legacy passthrough
    is available only through the dangerous ``allow_unsigned_output``
    compatibility option; strict mode always overrides that option.

    Args:
        client: An existing JacsClient instance. If None, one is
            created from config_path or via quickstart.
        config_path: Path to jacs.config.json (used only if client
            is None).
        strict: If True, signing failures reject the output and disable
            all passthrough compatibility options.
        allow_unsigned_output: Dangerous compatibility option that returns
            unsigned task output after a signing failure. Default False.
        allow_plain_signature_fallback: Permit failed attestation creation to
            downgrade to a plain signature. Default False.
        attest: If True, produce attestation documents.

    Returns:
        A guardrail function suitable for ``Task(guardrail=...)``.

    Example:
        task = Task(
            description="Analyze data",
            agent=analyst,
            guardrail=jacs_guardrail(client=jacs_client),
        )
    """
    adapter = BaseJacsAdapter(
        client=client,
        config_path=config_path,
        strict=strict,
        allow_unsigned_output=allow_unsigned_output,
        allow_plain_signature_fallback=allow_plain_signature_fallback,
        attest=attest,
    )

    def guardrail(result: Any) -> Tuple[bool, Any]:
        raw = getattr(result, "raw", None)
        if raw is None:
            raw = str(result)
        data = raw if isinstance(raw, str) else str(raw)

        try:
            signed = adapter.sign_output(data)
            return (True, signed)
        except Exception as exc:
            logger.warning("JACS guardrail signing failed: %s", exc)
            if adapter.allow_unsigned_output:
                return (True, data)
            return (False, f"JACS signing failed: {exc}")

    return guardrail


def signed_task(
    client: Optional[Any] = None,
    config_path: Optional[str] = None,
    strict: bool = False,
    allow_unsigned_output: bool = False,
    allow_plain_signature_fallback: bool = False,
    attest: bool = False,
    **task_kwargs: Any,
) -> Callable:
    """Decorator/factory that creates a CrewAI Task with a JACS guardrail.

    Can be used as a decorator on a function that returns Task kwargs,
    or called directly as a factory.

    Args:
        client: An existing JacsClient instance.
        config_path: Path to jacs.config.json.
        strict: Whether signing failures should reject the task and disable
            passthrough compatibility options.
        allow_unsigned_output: Dangerous compatibility option that returns
            unsigned task output after a signing failure. Default False.
        allow_plain_signature_fallback: Permit failed attestation creation to
            downgrade to a plain signature. Default False.
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

    guardrail_fn = jacs_guardrail(
        client=client,
        config_path=config_path,
        strict=strict,
        allow_unsigned_output=allow_unsigned_output,
        allow_plain_signature_fallback=allow_plain_signature_fallback,
        attest=attest,
    )

    if task_kwargs:
        if "guardrail" in task_kwargs:
            raise ValueError(
                "signed_task cannot safely replace an existing guardrail; "
                "compose it with jacs_guardrail explicitly"
            )
        task_kwargs["guardrail"] = guardrail_fn
        return Task(**task_kwargs)

    def decorator(fn: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> "Task":
            result = fn(*args, **kwargs)
            if isinstance(result, dict):
                if "guardrail" in result:
                    raise ValueError(
                        "signed_task cannot safely replace an existing guardrail; "
                        "compose it with jacs_guardrail explicitly"
                    )
                result["guardrail"] = guardrail_fn
                return Task(**result)
            # If the function already returns a Task, attach guardrail
            if isinstance(result, Task):
                if result.guardrail is not None:
                    raise ValueError(
                        "signed_task cannot safely replace an existing guardrail; "
                        "compose it with jacs_guardrail explicitly"
                    )
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
        strict: If True, signing failures raise and passthrough is disabled.
        allow_unsigned_output: Dangerous compatibility option that returns
            unsigned tool output after a signing failure. Default False.
        attest: If True, produce attestation documents.

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
        allow_unsigned_output: bool = False,
        allow_plain_signature_fallback: bool = False,
        attest: bool = False,
    ) -> None:
        self._inner = inner_tool
        self._adapter = BaseJacsAdapter(
            client=client,
            config_path=config_path,
            strict=strict,
            allow_unsigned_output=allow_unsigned_output,
            allow_plain_signature_fallback=allow_plain_signature_fallback,
            attest=attest,
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
        allow_unverified_passthrough: Dangerous compatibility opt-in that
            lets unverifiable input reach the wrapped tool. Default False.
    """

    def __init__(
        self,
        inner_tool: Any,
        client: Optional[Any] = None,
        config_path: Optional[str] = None,
        strict: bool = False,
        allow_unverified_passthrough: bool = False,
    ) -> None:
        self._inner = inner_tool
        self._adapter = BaseJacsAdapter(
            client=client,
            config_path=config_path,
            strict=strict,
            allow_unverified_passthrough=allow_unverified_passthrough,
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
