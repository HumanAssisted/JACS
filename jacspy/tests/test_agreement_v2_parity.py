import json

import pytest

jacs = pytest.importorskip("jacs")

from jacs import SimpleAgent


def _ephemeral(algorithm: str = "ed25519"):
    agent, info = SimpleAgent.ephemeral(algorithm=algorithm)
    return agent, info["agent_id"]


def _base_input(agent_id: str):
    return {
        "title": "Agreement v2 parity",
        "description": "Portable agreement v2 workflow test.",
        "terms": "The binding must delegate agreement v2 behavior to Rust core.",
        "termsFormat": "text/plain",
        "status": "proposed",
        "parties": [{"agentId": agent_id, "agentType": "ai", "role": "signer"}],
        "signaturePolicy": {
            "partyQuorum": "all",
            "witnessRequired": 0,
            "notaryRequired": 0,
            "requiredAlgorithms": ["ring-Ed25519"],
            "minimumStrength": "classical",
        },
        "controllers": [agent_id],
    }


def _create_agreement(agent, agent_id: str) -> str:
    return agent.create_agreement_v2(_base_input(agent_id))


def _document_ref(agent, message: str):
    signed = agent.sign_message({"message": message})
    raw = json.loads(signed["raw"])
    return {
        "jacsId": raw["jacsId"],
        "jacsVersion": raw["jacsVersion"],
        "jacsSha256": raw["jacsSha256"],
    }


def _apply(agent, document: str, mutation) -> str:
    return agent.apply_agreement_v2(document, mutation)


def test_agreement_v2_create_sign_verify_round_trip():
    agent, agent_id = _ephemeral()

    created = _create_agreement(agent, agent_id)
    signed = agent.sign_agreement_v2(created, "signer")
    report = agent.verify_agreement_v2(signed)

    assert report["valid"] is True
    assert report["expectedStatus"] == "final"
    assert report["signerCount"] == 1


def test_agreement_v2_notary_role_round_trip():
    signer, signer_id = _ephemeral()
    notary, notary_id = _ephemeral()
    input_doc = _base_input(signer_id)
    input_doc["parties"] = [
        {"agentId": signer_id, "agentType": "ai", "role": "signer"},
        {"agentId": notary_id, "agentType": "ai", "role": "notary"},
    ]
    input_doc["signaturePolicy"]["notaryRequired"] = 1

    created = signer.create_agreement_v2(input_doc)
    notarized = notary.sign_agreement_v2(created, "notary")
    document = json.loads(notarized)

    assert document["agreementSignatures"][0]["role"] == "notary"


def test_agreement_v2_transcript_branches_auto_merge():
    agent, agent_id = _ephemeral()
    base = _create_agreement(agent, agent_id)

    left = _apply(
        agent,
        base,
        {"type": "appendTranscript", "entry": _document_ref(agent, "left transcript")},
    )
    right = _apply(
        agent,
        base,
        {"type": "appendTranscript", "entry": _document_ref(agent, "right transcript")},
    )

    analysis = agent.detect_agreement_v2_branch_conflict(base, left, right)
    assert analysis["sameDocument"] is True
    assert analysis["sameParent"] is True
    assert analysis["autoMergeable"] is True

    merged = json.loads(agent.merge_agreement_v2_transcript_branches(base, left, right))
    assert len(merged["transcript"]) == 2


def test_agreement_v2_terms_conflict_requires_explicit_resolution():
    agent, agent_id = _ephemeral()
    base = _create_agreement(agent, agent_id)
    left = _apply(agent, base, {"type": "updateTerms", "terms": "Left branch terms."})
    right = _apply(agent, base, {"type": "updateTerms", "terms": "Right branch terms."})

    analysis = agent.detect_agreement_v2_branch_conflict(base, left, right)
    assert analysis["autoMergeable"] is False
    assert "terms" in analysis["conflictFields"]

    resolved = json.loads(
        agent.resolve_agreement_v2_branch_conflict(
            base,
            left,
            right,
            {"type": "updateTerms", "terms": "Resolved terms."},
        )
    )
    right_doc = json.loads(right)

    assert resolved["terms"] == "Resolved terms."
    assert resolved["links"][0] == {
        "jacsId": right_doc["jacsId"],
        "jacsVersion": right_doc["jacsVersion"],
    }
