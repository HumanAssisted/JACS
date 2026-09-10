"""
Behavioral tests for the ES256 compatibility key + ecosystem exports
(P2 Tasks 002 / 004) on the SimpleAgent PyO3 class.

New agents mint the ES256 `ecosystem_signing` compat key at creation, so
identity exports (JWKS, key binding) succeed on a fresh agent, while
content exports (AP2 mandate, Agreement-v2 VC) require an explicit
binding scope and are denied until one is granted (never auto-issued).
"""

from __future__ import annotations

import json

import pytest

jacs = pytest.importorskip("jacs")

from jacs import SimpleAgent

PASSWORD = "CompatKeyTest!2026"

# Sample UCP checkout that passes the ap2-mandate input schema.
SAMPLE_CHECKOUT = {
    "id": "c1",
    "currency": "USD",
    "line_items": [{"id": "li1"}],
    "totals": [{"type": "total", "amount": 100}],
}


@pytest.fixture
def agent(tmp_path, monkeypatch):
    """Fresh persistent agent: pq2025 native root + eagerly minted compat key."""
    monkeypatch.setenv("JACS_PRIVATE_KEY_PASSWORD", PASSWORD)
    params = {
        "name": "compat-exports-test",
        "password": PASSWORD,
        "data_directory": str(tmp_path / "jacs_data"),
        "key_directory": str(tmp_path / "jacs_keys"),
        "config_path": str(tmp_path / "jacs.config.json"),
    }
    instance, info = SimpleAgent.create_with_params(json.dumps(params))
    assert info["agent_id"], "agent creation should surface an agent_id"
    return instance


def test_jwks_export_returns_es256_p256_jwk(agent):
    """Identity export: JWKS succeeds on a fresh agent (auto-issued binding)."""
    jwks = json.loads(agent.export_compatibility_jwks())
    keys = jwks["keys"]
    assert len(keys) == 1, "JWKS publishes exactly the ES256 compat key"
    jwk = keys[0]
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert jwk.get("alg", "ES256") == "ES256"
    assert jwk["kid"], "JWK carries a non-empty kid"
    # PQ material is never published through the compatibility JWKS.
    assert "d" not in jwk, "private material must never appear in the JWKS"


def test_key_binding_export_is_pq_root_signed(agent):
    """Identity export: the binding traces the ES256 key to the pq2025 root."""
    binding = json.loads(agent.export_compatibility_key_binding())
    assert binding["jacsType"] == "compatibilityKeyBinding"
    body = binding["compatibilityKeyBinding"]
    assert body["rootKey"]["algorithm"] == "pq2025"
    assert body["compatibilityKey"]["algorithm"] == "ES256"
    assert body["compatibilityKey"]["publicJwk"]["crv"] == "P-256"
    # Signed by the native (post-quantum) root, not the compat key.
    assert binding["jacsSignature"]["agentID"], "binding carries a root signature"


def test_add_compat_key_rejects_duplicate(agent):
    """New agents mint the compat key at creation; re-minting is an error."""
    with pytest.raises(RuntimeError) as excinfo:
        agent.add_compat_key()
    msg = str(excinfo.value).lower()
    assert "already" in msg or "exists" in msg


def test_ap2_mandate_export_denied_without_scope(agent):
    """Content export: `ap2-mandate` scope is never auto-issued on a fresh agent."""
    with pytest.raises(RuntimeError) as excinfo:
        agent.export_ap2_mandate(json.dumps(SAMPLE_CHECKOUT))
    msg = str(excinfo.value).lower()
    assert "binding" in msg or "scope" in msg, (
        f"denial should name the missing binding/scope, got: {msg}"
    )


def test_ap2_mandate_export_succeeds_after_scope_grant(agent):
    """Content export happy path: an explicit `ap2-mandate` grant via
    issue_compat_binding unlocks export_ap2_mandate (Issue 003 parity)."""
    # Denial is asserted FIRST on the same fresh agent, so the grant below
    # is proven to be the thing that unlocks the export.
    with pytest.raises(RuntimeError):
        agent.export_ap2_mandate(json.dumps(SAMPLE_CHECKOUT))

    # Grant identity + ap2-mandate content scope, native-root-signed.
    binding = json.loads(
        agent.issue_compat_binding(
            ["jwks", "did", "a2a-agent-card", "w3c-agent-identity", "ap2-mandate"]
        )
    )
    assert binding["jacsType"] == "compatibilityKeyBinding"
    scopes = binding["compatibilityKeyBinding"]["scope"]
    assert "ap2-mandate" in scopes, f"grant must include ap2-mandate, got: {scopes}"

    export = json.loads(agent.export_ap2_mandate(json.dumps(SAMPLE_CHECKOUT)))
    assert export["format"] == "ap2-mandate"
    detached_jws = export["detachedJws"]
    header_b64, payload, sig_b64 = detached_jws.split(".")
    assert payload == "", "detached JWS must have an empty payload segment"
    assert header_b64 and sig_b64, "detached JWS must carry header and signature"


def test_issue_compat_binding_rejects_unknown_scope(agent):
    """Scope validation: an unknown scope is a Validation error, not a grant."""
    with pytest.raises(RuntimeError) as excinfo:
        agent.issue_compat_binding(["jwks", "not-a-real-scope"])
    assert "scope" in str(excinfo.value).lower()


@pytest.mark.skipif(
    not hasattr(SimpleAgent, "export_agreement_v2_as_vc"),
    reason="native extension built without the 'agreements' feature",
)
def test_agreement_vc_export_rejects_non_agreement_input(agent):
    """The VC export is typed: non-agreement input fails at the jacsType boundary."""
    with pytest.raises(RuntimeError) as excinfo:
        agent.export_agreement_v2_as_vc('{"foo": "bar"}')
    assert "jacsType" in str(excinfo.value)


@pytest.mark.skipif(
    not hasattr(SimpleAgent, "export_a2a_agent_card"),
    reason="native extension built without the 'a2a' feature",
)
def test_a2a_agent_card_export_succeeds(agent):
    """Identity export: the agent card is ES256-signed with a binding hash ref."""
    card = json.loads(agent.export_a2a_agent_card())
    assert card["metadata"]["jacsCompatBindingHash"]
