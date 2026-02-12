"""
Tests for jacs.a2a_discovery — A2A Agent Card discovery client (Task #20 / [2.3.3]).

Verifies:
- discover_agent() fetches and parses agent cards
- Error handling: unreachable, 404, non-JSON, non-object
- discover_and_assess() applies trust policies (open/verified/strict)
- JACS extension detection
- Sync wrappers
"""

import json

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from jacs.a2a_discovery import (
    discover_agent,
    discover_and_assess,
    discover_agent_sync,
    discover_and_assess_sync,
    AgentUnreachableError,
    InvalidAgentCardError,
    JACS_EXTENSION_URI,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

SAMPLE_CARD = {
    "name": "Remote Bot",
    "description": "A remote A2A agent",
    "version": "1.0",
    "protocolVersions": ["0.4.0"],
    "capabilities": {
        "extensions": [
            {
                "uri": JACS_EXTENSION_URI,
                "description": "JACS provenance",
            }
        ]
    },
    "metadata": {
        "jacsId": "remote-agent-42",
    },
    "skills": [],
}

SAMPLE_CARD_NO_JACS = {
    "name": "Vanilla Bot",
    "description": "An agent without JACS",
    "version": "1.0",
    "protocolVersions": ["0.4.0"],
    "capabilities": {},
    "skills": [],
}


def _mock_response(status_code: int = 200, json_data=None, text: str = ""):
    """Build a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = json.JSONDecodeError("err", "", 0)
    return resp


# ---------------------------------------------------------------------------
# Tests: discover_agent
# ---------------------------------------------------------------------------

class TestDiscoverAgent:
    @pytest.mark.asyncio
    async def test_fetches_and_returns_card(self):
        mock_resp = _mock_response(200, json_data=SAMPLE_CARD)

        with patch("jacs.a2a_discovery.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            card = await discover_agent("https://agent.example.com")

        assert card["name"] == "Remote Bot"
        instance.get.assert_called_once_with(
            "https://agent.example.com/.well-known/agent-card.json"
        )

    @pytest.mark.asyncio
    async def test_strips_trailing_slash(self):
        mock_resp = _mock_response(200, json_data=SAMPLE_CARD)

        with patch("jacs.a2a_discovery.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            await discover_agent("https://agent.example.com/")

        instance.get.assert_called_once_with(
            "https://agent.example.com/.well-known/agent-card.json"
        )

    @pytest.mark.asyncio
    async def test_raises_on_404(self):
        mock_resp = _mock_response(404)

        with patch("jacs.a2a_discovery.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            with pytest.raises(AgentUnreachableError, match="404"):
                await discover_agent("https://gone.example.com")

    @pytest.mark.asyncio
    async def test_raises_on_connect_error(self):
        with patch("jacs.a2a_discovery.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.side_effect = httpx.ConnectError("refused")
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            with pytest.raises(AgentUnreachableError, match="Cannot reach"):
                await discover_agent("https://down.example.com")

    @pytest.mark.asyncio
    async def test_raises_on_timeout(self):
        with patch("jacs.a2a_discovery.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.side_effect = httpx.TimeoutException("timed out")
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            with pytest.raises(AgentUnreachableError, match="Timeout"):
                await discover_agent("https://slow.example.com")

    @pytest.mark.asyncio
    async def test_raises_on_non_json(self):
        mock_resp = _mock_response(200)  # json() raises JSONDecodeError

        with patch("jacs.a2a_discovery.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            with pytest.raises(InvalidAgentCardError, match="not valid JSON"):
                await discover_agent("https://html.example.com")

    @pytest.mark.asyncio
    async def test_raises_on_non_object(self):
        mock_resp = _mock_response(200, json_data=["not", "an", "object"])

        with patch("jacs.a2a_discovery.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            with pytest.raises(InvalidAgentCardError, match="not a JSON object"):
                await discover_agent("https://array.example.com")


# ---------------------------------------------------------------------------
# Tests: discover_and_assess
# ---------------------------------------------------------------------------

class TestDiscoverAndAssess:
    @pytest.mark.asyncio
    async def test_open_policy_always_allows(self):
        with patch("jacs.a2a_discovery.discover_agent", new_callable=AsyncMock) as mock_disc:
            mock_disc.return_value = SAMPLE_CARD_NO_JACS

            result = await discover_and_assess(
                "https://vanilla.example.com", policy="open"
            )

        assert result["allowed"] is True
        assert result["jacs_registered"] is False
        assert result["trust_level"] == "untrusted"

    @pytest.mark.asyncio
    async def test_verified_allows_jacs_registered(self):
        with patch("jacs.a2a_discovery.discover_agent", new_callable=AsyncMock) as mock_disc:
            mock_disc.return_value = SAMPLE_CARD

            result = await discover_and_assess(
                "https://jacs-agent.example.com", policy="verified"
            )

        assert result["allowed"] is True
        assert result["jacs_registered"] is True
        assert result["trust_level"] == "jacs_registered"

    @pytest.mark.asyncio
    async def test_verified_rejects_non_jacs(self):
        with patch("jacs.a2a_discovery.discover_agent", new_callable=AsyncMock) as mock_disc:
            mock_disc.return_value = SAMPLE_CARD_NO_JACS

            result = await discover_and_assess(
                "https://vanilla.example.com", policy="verified"
            )

        assert result["allowed"] is False
        assert result["jacs_registered"] is False

    @pytest.mark.asyncio
    async def test_strict_requires_trust_store(self):
        mock_client = MagicMock()
        mock_client.is_trusted.return_value = True

        with patch("jacs.a2a_discovery.discover_agent", new_callable=AsyncMock) as mock_disc:
            mock_disc.return_value = SAMPLE_CARD

            result = await discover_and_assess(
                "https://trusted.example.com",
                policy="strict",
                client=mock_client,
            )

        assert result["allowed"] is True
        assert result["trust_level"] == "trusted"
        mock_client.is_trusted.assert_called_once_with("remote-agent-42")

    @pytest.mark.asyncio
    async def test_strict_rejects_untrusted(self):
        mock_client = MagicMock()
        mock_client.is_trusted.return_value = False

        with patch("jacs.a2a_discovery.discover_agent", new_callable=AsyncMock) as mock_disc:
            mock_disc.return_value = SAMPLE_CARD

            result = await discover_and_assess(
                "https://unknown.example.com",
                policy="strict",
                client=mock_client,
            )

        assert result["allowed"] is False
        assert result["trust_level"] == "jacs_registered"

    @pytest.mark.asyncio
    async def test_strict_without_client_rejects(self):
        """strict policy with no client (no trust store) always rejects."""
        with patch("jacs.a2a_discovery.discover_agent", new_callable=AsyncMock) as mock_disc:
            mock_disc.return_value = SAMPLE_CARD

            result = await discover_and_assess(
                "https://agent.example.com", policy="strict"
            )

        assert result["allowed"] is False

    @pytest.mark.asyncio
    async def test_invalid_policy_raises(self):
        with pytest.raises(ValueError, match="Invalid trust policy"):
            await discover_and_assess(
                "https://agent.example.com", policy="yolo"
            )

    @pytest.mark.asyncio
    async def test_card_returned_in_result(self):
        with patch("jacs.a2a_discovery.discover_agent", new_callable=AsyncMock) as mock_disc:
            mock_disc.return_value = SAMPLE_CARD

            result = await discover_and_assess(
                "https://agent.example.com", policy="open"
            )

        assert result["card"] is SAMPLE_CARD
        assert result["card"]["name"] == "Remote Bot"


# ---------------------------------------------------------------------------
# Tests: sync wrappers
# ---------------------------------------------------------------------------

class TestSyncWrappers:
    def test_discover_agent_sync(self):
        with patch("jacs.a2a_discovery.discover_agent", new_callable=AsyncMock) as mock_disc:
            mock_disc.return_value = SAMPLE_CARD

            card = discover_agent_sync("https://agent.example.com")

        assert card["name"] == "Remote Bot"

    def test_discover_and_assess_sync(self):
        with patch("jacs.a2a_discovery.discover_agent", new_callable=AsyncMock) as mock_disc:
            mock_disc.return_value = SAMPLE_CARD

            result = discover_and_assess_sync(
                "https://agent.example.com", policy="verified"
            )

        assert result["allowed"] is True
        assert result["jacs_registered"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
