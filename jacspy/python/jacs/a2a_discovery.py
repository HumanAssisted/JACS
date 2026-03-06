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

Requires ``httpx`` (install with ``pip install jacs[a2a]``).
"""

from __future__ import annotations

import asyncio
import logging
import os
import warnings
from typing import Any, Dict, Optional, TYPE_CHECKING

try:
    import httpx
except ImportError as _exc:
    raise ImportError(
        "jacs.a2a_discovery requires httpx. "
        "Install it with: pip install jacs[a2a]"
    ) from _exc

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
    base = url.rstrip("/")
    card_url = f"{base}{AGENT_CARD_PATH}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.get(card_url)
        except httpx.ConnectError as e:
            raise AgentUnreachableError(
                f"Cannot reach agent at {card_url}: {e}"
            ) from e
        except httpx.TimeoutException as e:
            raise AgentUnreachableError(
                f"Timeout fetching agent card from {card_url}: {e}"
            ) from e
        except httpx.HTTPError as e:
            raise AgentUnreachableError(
                f"HTTP error fetching {card_url}: {e}"
            ) from e

    if response.status_code == 404:
        raise AgentUnreachableError(
            f"No agent card found at {card_url} (404)"
        )

    if response.status_code >= 400:
        raise AgentUnreachableError(
            f"Agent returned HTTP {response.status_code} for {card_url}"
        )

    try:
        card = response.json()
    except Exception as e:
        raise InvalidAgentCardError(
            f"Response from {card_url} is not valid JSON: {e}"
        ) from e

    if not isinstance(card, dict):
        raise InvalidAgentCardError(
            f"Agent card at {card_url} is not a JSON object"
        )

    return card


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
        client: Optional ``JacsClient`` instance used for trust store
            lookups when ``policy="strict"``.
        timeout: HTTP request timeout in seconds.

    Returns:
        A dict with::

            {
                "card": <agent card dict>,
                "jacs_registered": bool,   # has JACS extension?
                "trust_level": str,        # "untrusted" | "jacs_registered" | "trusted"
                "allowed": bool,           # passes the policy?
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
            canonical_json = client._agent.assess_a2a_agent(
                _json.dumps(card), effective_policy
            )
            trust = _json.loads(canonical_json)
            return {
                "card": card,
                "jacs_registered": trust.get("jacsRegistered", False),
                "trust_level": trust.get("trustLevel", "untrusted"),
                "allowed": trust.get("allowed", False),
            }
        except (ImportError, AttributeError):
            logger.warning(
                "Falling back to local trust policy evaluation "
                "— binding-core assess_a2a_agent unavailable"
            )

    # Fallback: deprecated local logic when no client is available
    is_trusted = getattr(client, "is_trusted", None) if client is not None else None
    trust = _evaluate_trust_policy(
        card,
        policy=effective_policy,
        is_trusted=is_trusted,
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

    jacs_registered = _has_jacs_extension(card)
    trust_level = "jacs_registered" if jacs_registered else "untrusted"

    if (
        effective_policy == "strict"
        and callable(is_trusted)
        and jacs_registered
    ):
        agent_id = _extract_agent_id(card)
        if agent_id:
            try:
                if is_trusted(agent_id):
                    trust_level = "trusted"
            except Exception:
                logger.debug("Trust store lookup failed for %s", agent_id)

    if effective_policy == "open":
        allowed = True
    elif effective_policy == "verified":
        allowed = jacs_registered
    elif effective_policy == "strict":
        allowed = trust_level == "trusted"
    else:
        allowed = False

    return {
        "jacs_registered": jacs_registered,
        "trust_level": trust_level,
        "allowed": allowed,
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
