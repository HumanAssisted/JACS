"""Regression tests for fail-closed identity-bound A2A discovery wrappers."""

import json
from datetime import datetime, timezone
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
        "/.well-known/jacs-compat-binding.json": {
            "jacsSha256": "binding-hash",
            "compatibilityKeyBinding": {
                "issuedAt": datetime.now(timezone.utc).isoformat(),
                "expiresAt": None,
            },
        },
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


def _direct_pairs():
    """Synthetic native output; actual crypto/root trust is tested in Rust."""
    import base64
    import hashlib

    pub = base64.urlsafe_b64encode(bytes([7]) * 2592).decode()
    kid = base64.urlsafe_b64encode(hashlib.sha256(json.dumps(
        {"alg": "ML-DSA-87", "kty": "AKP", "pub": pub}, separators=(",", ":")
    ).encode()).digest()).decode().rstrip("=")
    header = base64.urlsafe_b64encode(json.dumps(
        {"alg": "ML-DSA-87", "kid": kid, "typ": "JOSE"}
    ).encode()).decode().rstrip("=")
    documents = {
        "/.well-known/agent-card.json": {
            "name": "native-root", "version": "1",
            "metadata": {"jacsId": "root-id", "jacsVersion": "1", "jacsRootKid": kid},
            "signatures": [{"keyId": kid, "jws": f"{header}.e30.c2ln"}],
        },
        "/.well-known/jwks.json": {"keys": [{"kid": kid, "kty": "AKP", "alg": "ML-DSA-87", "pub": pub, "use": "sig"}]},
        "/.well-known/jacs-agent.json": {"agentId": "root-id", "agentVersion": "1", "keyAlgorithm": "pq2025"},
        "/.well-known/jacs-pubkey.json": {
            "agentId": "root-id", "agentVersion": "1", "algorithm": "pq2025",
            "publicKey": base64.b64encode(bytes([7]) * 2592).decode(),
        },
        "/.well-known/jacs-extension.json": {"uri": "urn:jacs:provenance-v1"},
    }
    return [{"path": path, "document": doc} for path, doc in documents.items()]


def test_direct_root_documents_preserve_native_card_without_compatibility_binding():
    client = MagicMock()
    client._agent.generate_well_known_documents.return_value = json.dumps(_direct_pairs())
    documents = JACSA2AIntegration(client).generate_well_known_documents(_card(), "attacker-jws", "attacker-key", {})
    assert len(documents) == 5
    assert documents["/.well-known/agent-card.json"]["name"] == "native-root"
    assert "/.well-known/jacs-compat-binding.json" not in documents


@pytest.mark.parametrize("field,value", [
    ("kid", "other"), ("alg", "ML-DSA-65"), ("pub", "AA"), ("priv", "secret"), ("kty", "OKP"),
])
def test_direct_root_rejects_malformed_or_mismatched_jwk(field, value):
    pairs = _direct_pairs()
    pairs[1]["document"]["keys"][0][field] = value
    client = MagicMock()
    client._agent.generate_well_known_documents.return_value = json.dumps(pairs)
    with pytest.raises(RuntimeError, match="inconsistent ML-DSA-87"):
        JACSA2AIntegration(client).generate_well_known_documents(_card(), "", "", {})


@pytest.mark.parametrize("index,field,value", [
    (2, "agentId", "other"), (3, "publicKey", "other"),
    (0, "signatures", [{"keyId": "other", "jws": "e30.e30.c2ln"}]),
])
def test_direct_root_rejects_mismatched_discovery_documents(index, field, value):
    pairs = _direct_pairs()
    pairs[index]["document"][field] = value
    client = MagicMock()
    client._agent.generate_well_known_documents.return_value = json.dumps(pairs)
    with pytest.raises(RuntimeError, match="inconsistent ML-DSA-87"):
        JACSA2AIntegration(client).generate_well_known_documents(_card(), "", "", {})


def test_explicit_es256_is_forwarded_to_native_generator():
    client = MagicMock()
    client._agent.generate_well_known_documents.return_value = json.dumps(_bound_pairs())
    documents = JACSA2AIntegration(client).generate_well_known_documents(_card(), "", "", {}, "es256")
    client._agent.generate_well_known_documents.assert_called_once_with("es256")
    assert "/.well-known/jacs-compat-binding.json" in documents


@pytest.mark.parametrize("policy", ["verified", "strict"])
def test_direct_card_does_not_establish_remote_trust_without_native_assessor(policy):
    client = MagicMock()
    card = _direct_pairs()[0]["document"]
    card["capabilities"] = {"extensions": [{"uri": "urn:jacs:provenance-v1"}]}
    result = JACSA2AIntegration(client, trust_policy=policy).assess_remote_agent(json.dumps(card))
    assert result["allowed"] is False


def test_direct_root_server_cache_refreshes_without_binding_and_fails_closed(monkeypatch):
    from fastapi.testclient import TestClient
    from jacs.a2a_server import create_a2a_app

    now = [1767225600.0]
    monkeypatch.setattr("jacs.a2a_server.time.time", lambda: now[0])
    client = MagicMock()
    client._agent.get_agent_json.return_value = json.dumps({"jacsId": "root-id", "jacsName": "native-root"})
    client._agent.generate_well_known_documents.side_effect = lambda: json.dumps(_direct_pairs())
    http = TestClient(create_a2a_app(client))
    assert http.get("/.well-known/agent-card.json").status_code == 200
    assert http.get("/.well-known/jacs-compat-binding.json").status_code == 404
    now[0] += 6 * 24 * 60 * 60
    assert http.get("/.well-known/agent-card.json").status_code == 200
    assert client._agent.generate_well_known_documents.call_count == 2
    client._agent.generate_well_known_documents.side_effect = RuntimeError("native failed")
    now[0] += 7 * 24 * 60 * 60
    assert http.get("/.well-known/agent-card.json").status_code == 503


def test_legacy_source_discovery_delegates_to_configured_native_integration(monkeypatch):
    import importlib.util
    from pathlib import Path
    import jacs

    path = Path(__file__).parents[1] / "src" / "a2a.py"
    spec = importlib.util.spec_from_file_location("legacy_a2a", path)
    legacy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(legacy)
    monkeypatch.setattr(jacs, "load", lambda config: None, raising=False)
    client = MagicMock()
    client._agent.generate_well_known_documents.return_value = json.dumps(_direct_pairs())
    monkeypatch.setattr(JACSA2AIntegration, "from_config", lambda config: JACSA2AIntegration(client))

    integration = legacy.JACSA2AIntegration("test.config.json")
    documents = integration.generate_well_known_documents(_card(), "untrusted-jws", "untrusted-key", {})
    assert len(documents) == 5
    assert documents["/.well-known/agent-card.json"]["name"] == "native-root"
    with pytest.raises(RuntimeError, match="requires a configured native"):
        legacy.JACSA2AIntegration().generate_well_known_documents(_card(), "jws", "key", {})
