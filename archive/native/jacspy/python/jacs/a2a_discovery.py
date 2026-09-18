"""
A2A Agent Card Discovery Client.

Fetch and assess remote A2A agents by retrieving their
``/.well-known/agent-card.json`` and checking for JACS provenance
support.

Usage::

    from jacs.a2a_discovery import discover_agent, discover_and_assess

    # Async
    card = await discover_agent("https://agent.example.com")

    # Async with trust assessment
    result = await discover_and_assess(
        "https://agent.example.com",
        policy="verified",
    )
    if result["allowed"]:
        print(f"Trusted agent: {result['card']['name']}")

    # Sync wrappers
    from jacs.a2a_discovery import discover_agent_sync, discover_and_assess_sync
    card = discover_agent_sync("https://agent.example.com")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import warnings
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .client import JacsClient

logger = logging.getLogger("jacs.a2a_discovery")

JACS_EXTENSION_URI = "urn:jacs:provenance-v1"
AGENT_CARD_PATH = "/.well-known/agent-card.json"
VALID_TRUST_POLICIES = ("open", "verified", "strict")


class DiscoveryError(Exception):
    """Raised when agent card discovery fails."""


class AgentUnreachableError(DiscoveryError):
    """Remote agent could not be contacted."""


class InvalidAgentCardError(DiscoveryError):
    """Response was not valid JSON or missing required fields."""


def _ensure_rust_network_access(capability: str) -> None:
    from . import ensure_network_access as _ensure_network_access

    _ensure_network_access(capability)


def _fetch_agent_card_json(url: str, timeout: float) -> str:
    from . import fetch_agent_card as _fetch_agent_card_native

    timeout_ms = max(1, int(timeout * 1000))
    return _fetch_agent_card_native(url, timeout_ms)


def _raise_discovery_error(exc: Exception) -> None:
    message = str(exc)
    lowered = message.lower()
    if (
        "not valid json" in lowered
        or "not a json object" in lowered
        or "not json" in lowered
    ):
        raise InvalidAgentCardError(message) from exc
    if (
        "404" in message
        or "unreachable" in lowered
        or "timed out" in lowered
        or "request failed" in lowered
        or "http " in lowered
    ):
        raise AgentUnreachableError(message) from exc
    raise DiscoveryError(message) from exc


# ---------------------------------------------------------------------------
# Core async API
# ---------------------------------------------------------------------------


async def discover_agent(
    url: str,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Fetch an A2A Agent Card from a remote URL.

    Retrieves ``{url}/.well-known/agent-card.json`` and parses it.

    Args:
        url: Base URL of the remote agent (e.g. ``"https://agent.example.com"``).
            A trailing slash is stripped automatically.
        timeout: HTTP request timeout in seconds (default 10).

    Returns:
        The parsed Agent Card as a dict.

    Raises:
        AgentUnreachableError: Network error or non-2xx status.
        InvalidAgentCardError: Response is not valid JSON.
    """
    try:
        _ensure_rust_network_access("agent_card_fetch")
    except Exception as e:
        raise DiscoveryError(str(e)) from e

    try:
        card_json = await asyncio.to_thread(_fetch_agent_card_json, url, timeout)
    except Exception as e:
        _raise_discovery_error(e)

    try:
        return json.loads(card_json)
    except Exception as e:
        raise InvalidAgentCardError(
            f"Response from {url.rstrip('/')}{AGENT_CARD_PATH} is not valid JSON: {e}"
        ) from e


async def discover_and_assess(
    url: str,
    policy: str = "verified",
    client: Optional["JacsClient"] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Fetch an A2A Agent Card and assess trust.

    Combines :func:`discover_agent` with a trust policy check.

    Args:
        url: Base URL of the remote agent.
        policy: Trust policy to apply — ``"open"``, ``"verified"``
            (default), or ``"strict"``.
        client: ``JacsClient`` whose native assessor performs JWS/JWKS,
            TOFU-pin, and strict compatibility-binding verification. Without
            it, only ``open`` can allow a result.
        timeout: HTTP request timeout in seconds.

    Returns:
        A dict with::

            {
                "card": <agent card dict>,
                "jacs_registered": bool,   # has JACS extension?
                "trust_level": str,        # "untrusted" | "jacs_registered" | "trusted"
                "allowed": bool,           # passes the policy?
                "first_contact": bool,     # TOFU key was pinned on this assessment?
            }

    Raises:
        DiscoveryError: If the agent card cannot be fetched.
        ValueError: If *policy* is not one of the three valid values.
    """
    effective_policy = _validate_trust_policy(policy)

    card = await discover_agent(url, timeout=timeout)

    # Prefer binding-core delegation when a JacsClient is available
    if client is not None and hasattr(client, "_agent"):
        import json as _json
        try:
            canonical_json = await asyncio.to_thread(
                client._agent.assess_a2a_agent,
                _json.dumps(card),
                effective_policy,
            )
            trust = _json.loads(canonical_json)
            allowed = trust.get("allowed") is True
            return {
                "card": card,
                "jacs_registered": trust.get("jacsRegistered") is True,
                "trust_level": trust.get("trustLevel", "untrusted") if allowed else "Untrusted",
                "allowed": allowed,
                "reason": trust.get("reason", ""),
                "first_contact": trust.get("firstContact") is True,
            }
        except Exception as exc:
            logger.warning(
                "Native A2A trust assessment unavailable; failing identity policy closed: %s",
                exc,
            )

    # No wrapper-only shortcut may turn an extension or trust-store boolean
    # into verified identity. The fallback is informational under `open` and
    # fail-closed for `verified`/`strict`.
    trust = _evaluate_trust_policy(
        card,
        policy=effective_policy,
        is_trusted=None,
    )

    return {
        "card": card,
        **trust,
    }


# ---------------------------------------------------------------------------
# Sync wrappers
# ---------------------------------------------------------------------------


def discover_agent_sync(
    url: str,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Synchronous wrapper for :func:`discover_agent`."""
    return _run_sync(discover_agent(url, timeout=timeout))


def discover_and_assess_sync(
    url: str,
    policy: str = "verified",
    client: Optional["JacsClient"] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Synchronous wrapper for :func:`discover_and_assess`."""
    return _run_sync(
        discover_and_assess(url, policy=policy, client=client, timeout=timeout)
    )


def _run_sync(coro: Any) -> Any:
    """Run a coroutine from sync code without dropping the thread's loop.

    Python 3.11's ``asyncio.run()`` clears the thread-local current loop
    after completion, which breaks older call sites that still rely on
    ``asyncio.get_event_loop()`` in the same thread.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    if loop.is_running():
        raise RuntimeError(
            "discover_*_sync cannot run inside an active event loop. "
            "Use the async discover_* APIs instead."
        )

    return loop.run_until_complete(coro)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _has_jacs_extension(card: Dict[str, Any]) -> bool:
    """Check whether an Agent Card declares the JACS provenance extension."""
    capabilities = card.get("capabilities", {})
    if not isinstance(capabilities, dict):
        return False

    extensions = capabilities.get("extensions", [])
    if not isinstance(extensions, list):
        return False

    for ext in extensions:
        if isinstance(ext, dict) and ext.get("uri") == JACS_EXTENSION_URI:
            return True

    return False


def _extract_agent_id(card: Dict[str, Any]) -> Optional[str]:
    """Try to extract the JACS agent ID from an Agent Card's metadata."""
    metadata = card.get("metadata", {})
    if isinstance(metadata, dict):
        agent_id = metadata.get("jacsId")
        if agent_id:
            return str(agent_id)
    return None


def _validate_trust_policy(policy: str) -> str:
    """Validate and normalize trust policy strings."""
    if policy not in VALID_TRUST_POLICIES:
        raise ValueError(
            f"Invalid trust policy: {policy!r}. "
            "Must be 'open', 'verified', or 'strict'."
        )
    return policy


def _evaluate_trust_policy(
    card: Dict[str, Any],
    policy: str = "verified",
    is_trusted: Optional[Any] = None,
) -> Dict[str, Any]:
    """Evaluate trust policy for a parsed Agent Card.

    .. deprecated::
        Use binding-core's ``assess_a2a_agent()`` via
        ``JACSA2AIntegration.assess_remote_agent()`` instead.
        This function is kept for backward compatibility with
        ``discover_and_assess()`` but will be removed in a future version.

    Returns:
        {
            "jacs_registered": bool,
            "trust_level": "untrusted" | "jacs_registered" | "trusted",
            "allowed": bool,
        }
    """
    if os.environ.get("JACS_SHOW_DEPRECATIONS"):
        warnings.warn(
            "_evaluate_trust_policy() is deprecated. "
            "Use binding-core's assess_a2a_agent() via "
            "JACSA2AIntegration.assess_remote_agent() instead.",
            DeprecationWarning,
            stacklevel=2,
        )

    effective_policy = _validate_trust_policy(policy)

    _ = is_trusted
    jacs_registered = _has_jacs_extension(card)
    trust_level = "untrusted"
    allowed = effective_policy == "open"
    reason = (
        "Open policy: agent allowed without native cryptographic assessment; "
        "no identity assurance is claimed"
        if allowed
        else f"{effective_policy.capitalize()} policy: native cryptographic assessment "
        "is unavailable; an Agent Card extension or trust-store name alone does not prove identity"
    )

    return {
        "jacs_registered": jacs_registered,
        "trust_level": trust_level,
        "allowed": allowed,
        "reason": reason,
        "first_contact": False,
    }


__all__ = [
    "discover_agent",
    "discover_and_assess",
    "discover_agent_sync",
    "discover_and_assess_sync",
    "DiscoveryError",
    "AgentUnreachableError",
    "InvalidAgentCardError",
    "JACS_EXTENSION_URI",
]
