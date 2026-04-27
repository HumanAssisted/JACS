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
# NOTE: do NOT import ``MissingSignatureError`` from ``.types`` here — the
# native Rust module has already injected the canonical PyO3-created class
# (via ``pyo3::create_exception!``) into ``jacs.MissingSignatureError``.
# Re-importing the pure-Python shim would silently shadow it with a different
# class, breaking ``except jacs.MissingSignatureError:`` for errors actually
# raised by strict-mode verify_text / verify_image.
from .types import (
    AgentInfo,
    Attachment,
    SignedDocument,
    VerificationResult,
    PublicKeyInfo,
    JacsError,
    ConfigError,
    AgentNotLoadedError,
    SigningError,
    VerificationError,
    TrustError,
    KeyNotFoundError,
    NetworkError,
    SignatureEntry,
    SignTextResult,
    VerifyTextResult,
    SignImageResult,
    VerifyImageResult,
)

# Make instance-based client API available
from .client import JacsClient

# Make simplified API available as jacs.simple
from . import simple

# Make async API available as jacs.async_simple
from . import async_simple

# Make MCP helpers available (optional, may fail if fastmcp not installed)
try:
    from . import mcp
except ImportError:
    mcp = None  # fastmcp not installed

# Make framework adapters available (optional, no hard deps)
from . import adapters

# Allow namespace package extensions (e.g., jacs.hai from haisdk)
__path__ = __import__('pkgutil').extend_path(__path__, __name__)

__all__ = [
    # Primary API Classes
    "JacsAgent",
    "JacsClient",
    "SimpleAgent",
    # Stateless utilities
    "hash_string",
    "hash_public_key_base64",
    "build_jwk_set_from_public_key",
    "ensure_network_access",
    "resolve_private_key_password",
    "quickstart_private_key_password",
    "verify_string",
    # Trust store
    "trust_agent",
    "trust_agent_with_key",
    "list_trusted_agents",
    "untrust_agent",
    "is_trusted",
    "get_trusted_agent",
    # Type definitions
    "AgentInfo",
    "Attachment",
    "SignedDocument",
    "VerificationResult",
    "PublicKeyInfo",
    # Error types
    "JacsError",
    "ConfigError",
    "AgentNotLoadedError",
    "SigningError",
    "VerificationError",
    "TrustError",
    "KeyNotFoundError",
    "NetworkError",
    "MissingSignatureError",
    "SignatureEntry",
    "SignTextResult",
    "VerifyTextResult",
    "SignImageResult",
    "VerifyImageResult",
    # Submodules
    "simple",
    "async_simple",
    "testing",
    "adapters",
]

 
