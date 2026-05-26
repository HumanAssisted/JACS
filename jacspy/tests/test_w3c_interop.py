from __future__ import annotations

import json

import pytest

jacs = pytest.importorskip("jacs")

from jacs import SimpleAgent


ORIGIN = "https://agent.example.com"
REQUEST_URL = "https://api.example.com/tasks?priority=high"
REQUEST_BODY = '{"task":"review proposal","ok":true}'
CREATED = "2026-01-01T00:00:00Z"
MAX_AGE_SECONDS = 4_000_000_000


def test_python_w3c_did_discovery_and_request_proof_round_trip():
    agent, _info = SimpleAgent.ephemeral("ed25519")

    did = agent.export_w3c_did(ORIGIN)
    assert did.startswith("did:wba:agent.example.com:agent:")

    did_document = agent.export_w3c_did_document(ORIGIN)
    assert did_document["id"] == did
    assert did_document["jacs"]["jacsId"]

    agent_description = agent.export_w3c_agent_description(ORIGIN)
    assert agent_description["did"] == did
    assert agent_description["jacs"]["jacsId"] == did_document["jacs"]["jacsId"]

    well_known = agent.generate_w3c_well_known(ORIGIN)
    assert "/.well-known/agent-descriptions" in well_known
    assert did in json.dumps(well_known, sort_keys=True)

    proof = agent.sign_w3c_request(
        "POST",
        REQUEST_URL,
        body=REQUEST_BODY,
        nonce="python-w3c-smoke-nonce",
        created=CREATED,
        origin=ORIGIN,
    )
    assert proof["did"] == did
    assert proof["contentDigest"].startswith("sha-256=:")

    proof_json = json.dumps(proof)
    did_document_json = json.dumps(did_document)

    with pytest.raises(Exception):
        agent.verify_w3c_request(
            proof_json,
            did_document_json,
            body=REQUEST_BODY,
            max_age_seconds=MAX_AGE_SECONDS,
            method="POST",
            url="https://api.example.com/other",
        )

    verification = agent.verify_w3c_request(
        proof_json,
        did_document_json,
        body=REQUEST_BODY,
        max_age_seconds=MAX_AGE_SECONDS,
        method="POST",
        url=REQUEST_URL,
    )
    assert verification["valid"] is True
    assert verification["expectedRequestChecked"] is True
