"""JACS Framework Adapters.

Provides base classes and framework-specific adapters for integrating
JACS cryptographic signing and verification into Python frameworks.

Usage:
    from jacs.adapters.base import BaseJacsAdapter
    from jacs.adapters.crewai import jacs_guardrail, JacsSignedTool
    from jacs.adapters.fastapi import JacsMiddleware, jacs_route
    from jacs.adapters.langchain import jacs_signing_middleware, JacsSigningMiddleware
"""

from .base import BaseJacsAdapter

__all__ = ["BaseJacsAdapter"]

try:
    from .crewai import JacsSignedTool, JacsVerifiedInput, jacs_guardrail, signed_task

    __all__ += ["jacs_guardrail", "signed_task", "JacsSignedTool", "JacsVerifiedInput"]
except ImportError:
    pass

try:
    from .fastapi import JacsMiddleware, jacs_route

    __all__ += ["JacsMiddleware", "jacs_route"]
except ImportError:
    pass

try:
    from .anthropic import JacsToolHook, signed_tool

    __all__ += ["signed_tool", "JacsToolHook"]
except ImportError:
    pass

try:
    from .langchain import (
        JacsSigningMiddleware,
        jacs_awrap_tool_call,
        jacs_signing_middleware,
        jacs_wrap_tool_call,
        signed_tool as langchain_signed_tool,
        with_jacs_signing,
    )

    __all__ += [
        "jacs_signing_middleware",
        "JacsSigningMiddleware",
        "jacs_wrap_tool_call",
        "jacs_awrap_tool_call",
        "langchain_signed_tool",
        "with_jacs_signing",
    ]
except ImportError:
    pass
