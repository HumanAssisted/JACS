import json
from pathlib import Path

import pytest

jacs = pytest.importorskip("jacs")

from jacs import SimpleAgent


FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "binding-core"
        / "tests"
        / "fixtures"
        / "agreement_v2_scenarios.json"
    ).read_text(encoding="utf-8")
)


def _ephemeral(algorithm: str = "ed25519"):
    agent, info = SimpleAgent.ephemeral(algorithm=algorithm)
    return agent, info["agent_id"]


def _base_input(agent_id: str):
    input_doc = json.loads(json.dumps(FIXTURE["base_input"]))
    input_doc["parties"] = [{"agentId": agent_id, "agentType": "ai", "role": "signer"}]
    input_doc["controllers"] = [agent_id]
    return input_doc


def _create_agreement(agent, agent_id: str) -> str:
    return agent.create_agreement_v2(_base_input(agent_id))


def _transcript_ref(name: str):
    return json.loads(json.dumps(FIXTURE["transcript_refs"][name]))


def _terms(name: str) -> str:
    return FIXTURE["terms_conflict"][name]


def _expected():
    return FIXTURE["expected"]


def _apply(agent, document: str, mutation) -> str:
    return agent.apply_agreement_v2(document, mutation)


def test_agreement_v2_create_sign_verify_round_trip():
    agent, agent_id = _ephemeral()

    created = _create_agreement(agent, agent_id)
    signed = agent.sign_agreement_v2(created, "signer")
    report = agent.verify_agreement_v2(signed)

    assert report["valid"] == _expected()["verify"]["valid"]
    assert report["expectedStatus"] == _expected()["verify"]["expectedStatus"]
    assert report["signerCount"] == _expected()["verify"]["signerCount"]


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

    assert document["agreementSignatures"][0]["role"] == _expected()["notary"]["role"]


def test_agreement_v2_transcript_branches_auto_merge():
    agent, agent_id = _ephemeral()
    base = _create_agreement(agent, agent_id)

    left = _apply(
        agent,
        base,
        {"type": "appendTranscript", "entry": _transcript_ref("left")},
    )
    right = _apply(
        agent,
        base,
        {"type": "appendTranscript", "entry": _transcript_ref("right")},
    )

    analysis = agent.detect_agreement_v2_branch_conflict(base, left, right)
    assert analysis["sameDocument"] == _expected()["transcriptMerge"]["sameDocument"]
    assert analysis["sameParent"] == _expected()["transcriptMerge"]["sameParent"]
    assert analysis["autoMergeable"] == _expected()["transcriptMerge"]["autoMergeable"]

    merged = json.loads(agent.merge_agreement_v2_transcript_branches(base, left, right))
    assert len(merged["transcript"]) == _expected()["transcriptMerge"]["mergedTranscriptLength"]


def test_agreement_v2_terms_conflict_requires_explicit_resolution():
    agent, agent_id = _ephemeral()
    base = _create_agreement(agent, agent_id)
    left = _apply(agent, base, {"type": "updateTerms", "terms": _terms("left")})
    right = _apply(agent, base, {"type": "updateTerms", "terms": _terms("right")})

    analysis = agent.detect_agreement_v2_branch_conflict(base, left, right)
    assert analysis["autoMergeable"] == _expected()["termsConflict"]["autoMergeable"]
    assert _expected()["termsConflict"]["conflictField"] in analysis["conflictFields"]

    resolved = json.loads(
        agent.resolve_agreement_v2_branch_conflict(
            base,
            left,
            right,
            {"type": "updateTerms", "terms": _terms("resolved")},
        )
    )
    right_doc = json.loads(right)

    assert resolved["terms"] == _terms("resolved")
    assert resolved["links"][0] == {
        "jacsId": right_doc["jacsId"],
        "jacsVersion": right_doc["jacsVersion"],
    }
