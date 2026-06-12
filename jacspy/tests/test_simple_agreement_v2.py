import json

import pytest

jacs = pytest.importorskip("jacs")

import jacs.simple as simple


# The native Agreement v2 methods require the package to be built with the
# "agreements" feature (see jacspy/pyproject.toml [tool.maturin] features).
# Skip cleanly when the installed extension was built without it.
_HAS_V2 = hasattr(jacs.SimpleAgent, "create_agreement_v2")
pytestmark = pytest.mark.skipif(
    not _HAS_V2,
    reason="native extension built without the 'agreements' feature",
)


@pytest.fixture
def loaded(tmp_path, monkeypatch):
    """Create and load a persistent global agent for module-level calls."""
    monkeypatch.setenv("JACS_PRIVATE_KEY_PASSWORD", "AgreementV2Test!2026")
    simple.reset()
    simple.create(
        name="agreement-v2-test",
        password="AgreementV2Test!2026",
        algorithm="ring-Ed25519",
        data_directory=str(tmp_path / "jacs_data"),
        key_directory=str(tmp_path / "jacs_keys"),
        config_path=str(tmp_path / "jacs.config.json"),
    )
    info = simple.get_agent_info()
    yield info.agent_id
    simple.reset()


def _agreement_input(agent_id: str) -> dict:
    return {
        "title": "Refund approval",
        "description": "Approval for a bounded refund.",
        "terms": "Refund up to $25 for order 123.",
        "status": "proposed",
        "parties": [{"agentId": agent_id, "agentType": "ai", "role": "signer"}],
        "signaturePolicy": {
            "partyQuorum": "all",
            "witnessRequired": 0,
            "notaryRequired": 0,
        },
        "controllers": [agent_id],
    }


def test_module_level_create_sign_verify_round_trip(loaded):
    agent_id = loaded

    agreement = simple.create_agreement_v2(_agreement_input(agent_id))
    assert isinstance(agreement, str)

    signed = simple.sign_agreement_v2(agreement, "signer")
    assert isinstance(signed, str)

    report = simple.verify_agreement_v2(signed)
    assert report["valid"] is True
    assert report["expectedStatus"] == "final"
    assert report["signerCount"] == 1


def test_module_level_accepts_dict_document(loaded):
    agent_id = loaded
    agreement = simple.create_agreement_v2(_agreement_input(agent_id))
    # Pass a dict (not a JSON string) to confirm normalization.
    report = simple.verify_agreement_v2(json.loads(agreement))
    assert "valid" in report


def test_module_level_apply_transcript_keeps_agreement_hash(loaded):
    agent_id = loaded
    agreement = simple.create_agreement_v2(_agreement_input(agent_id))
    statement = simple.sign_message({"forRecord": "context note"})
    raw = json.loads(statement.raw_json)
    entry = {
        "jacsId": raw["jacsId"],
        "jacsVersion": raw["jacsVersion"],
        "jacsSha256": raw["jacsSha256"],
    }
    updated = simple.apply_agreement_v2(
        agreement, {"type": "appendTranscript", "entry": entry}
    )
    before = json.loads(agreement)["jacsAgreementHash"]
    after = json.loads(updated)["jacsAgreementHash"]
    assert before == after


def test_module_level_functions_exported():
    for name in [
        "create_agreement_v2",
        "apply_agreement_v2",
        "sign_agreement_v2",
        "verify_agreement_v2",
        "detect_agreement_v2_branch_conflict",
        "merge_agreement_v2_transcript_branches",
        "resolve_agreement_v2_branch_conflict",
    ]:
        assert name in simple.__all__
        assert callable(getattr(simple, name))
