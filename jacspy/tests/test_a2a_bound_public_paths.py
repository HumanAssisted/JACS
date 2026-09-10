"""Regression tests for fail-closed identity-bound A2A discovery wrappers."""

import json
from unittest.mock import MagicMock

import pytest

from jacs.a2a import (
    A2AAgentCapabilities,
    A2AAgentCard,
    A2AAgentInterface,
    JACSA2AIntegration,
)


def _card() -> A2AAgentCard:
    return A2AAgentCard(
        name="caller-controlled",
        description="must not replace the native signed card",
        version="1",
        protocol_versions=["0.4.0"],
        supported_interfaces=[A2AAgentInterface("https://attacker.invalid", "jsonrpc")],
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        capabilities=A2AAgentCapabilities(),
        skills=[],
    )


def _bound_pairs() -> list[dict]:
    documents = {
        "/.well-known/agent-card.json": {
            "name": "native-bound",
            "metadata": {
                "jacsCompatKid": "compat-kid",
                "jacsCompatBindingHash": "binding-hash",
                "jacsCompatBindingPath": "/.well-known/jacs-compat-binding.json",
            },
            "signatures": [{"keyId": "compat-kid", "jws": "native-es256-jws"}],
        },
        "/.well-known/jwks.json": {
            "keys": [{"kid": "compat-kid", "alg": "ES256", "use": "sig"}],
        },
        "/.well-known/jacs-compat-binding.json": {"jacsSha256": "binding-hash"},
        "/.well-known/jacs-agent.json": {"agentId": "native-id"},
        "/.well-known/jacs-pubkey.json": {"agentId": "native-id"},
        "/.well-known/jacs-extension.json": {"uri": "urn:jacs:provenance-v1"},
    }
    return [{"path": path, "document": document} for path, document in documents.items()]


def test_native_bound_card_is_not_overwritten_by_caller_card_or_jws():
    client = MagicMock()
    client._agent.generate_well_known_documents.return_value = json.dumps(_bound_pairs())
    integration = JACSA2AIntegration(client)

    documents = integration.generate_well_known_documents(
        _card(),
        "attacker-jws",
        "attacker-key",
        {"jacsId": "copied-id"},
    )

    assert len(documents) == 6
    assert documents["/.well-known/agent-card.json"]["name"] == "native-bound"
    assert documents["/.well-known/agent-card.json"]["signatures"] == [
        {"keyId": "compat-kid", "jws": "native-es256-jws"}
    ]


def test_native_generation_error_never_falls_back_to_unbound_documents():
    client = MagicMock()
    client._agent.generate_well_known_documents.side_effect = RuntimeError("native failed")
    integration = JACSA2AIntegration(client)

    with pytest.raises(RuntimeError, match="Identity-bound A2A discovery generation failed"):
        integration.generate_well_known_documents(_card(), "jws", "key", {})


def test_missing_native_generator_fails_closed():
    client = MagicMock()
    integration = JACSA2AIntegration(client)

    with pytest.raises(RuntimeError, match="requires the native JACS generator"):
        integration.generate_well_known_documents(_card(), "jws", "key", {})


def test_fastapi_routes_serve_the_native_signed_card_unchanged():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from jacs.a2a_server import jacs_a2a_routes

    client = MagicMock()
    client._agent.get_agent_json.return_value = json.dumps({
        "jacsId": "wrapper-id",
        "jacsVersion": "1",
        "jacsName": "wrapper-name",
        "jacsDescription": "wrapper description",
        "jacsAgentType": "ai",
    })
    client._agent.generate_well_known_documents.return_value = json.dumps(_bound_pairs())
    app = FastAPI()
    app.include_router(jacs_a2a_routes(client))

    response = TestClient(app).get("/.well-known/agent-card.json")
    assert response.status_code == 200
    assert response.json()["name"] == "native-bound"
    assert response.json()["signatures"] == [
        {"keyId": "compat-kid", "jws": "native-es256-jws"}
    ]
