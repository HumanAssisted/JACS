"""
JACS - JSON AI Communication Standard

Python bindings for cryptographic signing and verification.

Quick Start:
    # Simplified API (recommended)
    import jacs.simple as jacs

    agent = jacs.load("./jacs.config.json")
    signed = jacs.sign_message("Hello!")
    result = jacs.verify(signed.raw_json)

    # Or use the JacsAgent class directly
    from jacs import JacsAgent

    agent = JacsAgent()
    agent.load("./jacs.config.json")
    sig = agent.sign_string("Hello!")
"""

import sys
import os

# Import the Rust module
try:
    # Direct import - should work when properly installed via pip
    from jacs.jacs import *  # noqa: F403, F401
except ImportError:
    try:
        # For development environment
        import importlib.util
        import os.path

        # Get the directory containing this __init__.py file
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Look for the .so file (platform specific)
        if sys.platform == "linux":
            so_path = os.path.join(current_dir, "linux", "jacspylinux.so")
            module_name = "jacspylinux"
        else:
            so_path = os.path.join(current_dir, "jacs.abi3.so")  # macOS
            module_name = "jacs.abi3"

        if os.path.exists(so_path):
            # Load the module dynamically
            spec = importlib.util.spec_from_file_location(module_name, so_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Copy all public attributes to the current module
            for attr in dir(module):
                if not attr.startswith('_'):
                    globals()[attr] = getattr(module, attr)
        else:
            raise ImportError(f"Could not find extension module at {so_path}")
    except Exception as e:
        raise ImportError(f"Failed to import the jacs extension module: {str(e)}")

# Import type definitions
from .types import (
    AgentInfo,
    Attachment,
    SignedDocument,
    VerificationResult,
    JacsError,
    ConfigError,
    AgentNotLoadedError,
    SigningError,
    VerificationError,
    TrustError,
)

# Make simplified API available as jacs.simple
from . import simple

# Make MCP helpers available (optional, may fail if fastmcp not installed)
try:
    from . import mcp_simple
except ImportError:
    mcp_simple = None  # fastmcp not installed

__all__ = [
    # Rust bindings (JacsAgent class and legacy functions)
    "JacsAgent",
    "load",
    "sign_string",
    "verify_string",
    "hash_string",
    "sign_agent",
    "verify_agent",
    "create_document",
    "verify_document",
    "sign_request",
    "verify_response",
    # Type definitions
    "AgentInfo",
    "Attachment",
    "SignedDocument",
    "VerificationResult",
    # Error types
    "JacsError",
    "ConfigError",
    "AgentNotLoadedError",
    "SigningError",
    "VerificationError",
    "TrustError",
    # Submodules
    "simple",
]

 
