#!/usr/bin/env python3
"""Inspect v2 signatures without accepting policy or claiming human approval.

All identities, including the demo notary, are controlled by this script.
Keys are temporary and the system keychain is disabled for the demo.

Run from the repository root after installing/building the Python package:

    python examples/agreement_v2_three_party.py
"""

import json
import os
import secrets
import shutil
import tempfile
from pathlib import Path

from jacs import SimpleAgent


def create_agent(name: str, base: str, password: str):
    key_dir = Path(base) / f"{name}_keys"
    config_path = Path(base) / f"{name}.config.json"
    agent, info = SimpleAgent.create_agent(
        name=name,
        password=password,
        algorithm="ring-Ed25519",
        data_directory=str(Path(base) / "shared_data"),
        key_directory=str(key_dir),
        config_path=str(config_path),
        agent_type="ai",
        description=f"{name} agreement v2 demo agent",
        default_storage="fs",
    )
    return agent, info


def doc_ref(signed_document: dict) -> dict:
    raw = json.loads(signed_document["raw"])
    return {
        "jacsId": raw["jacsId"],
        "jacsVersion": raw["jacsVersion"],
        "jacsSha256": raw["jacsSha256"],
    }


def expect_rejected(label: str, reason: str, fn) -> None:
    try:
        fn()
    except Exception as exc:
        if reason not in str(exc):
            raise AssertionError(f"unexpected failure for {label}: {exc}") from exc
        print(f"  rejected {label}: {str(exc).splitlines()[0]}")
        return
    raise AssertionError(f"expected rejection: {label}")


def assert_policy_unaccepted(report: dict) -> None:
    assert report["valid"] is False, report
    assert report["policyAccepted"] is False, report
    assert report["overallScope"] == "consent_signatures_only", report


def main() -> None:
    base = tempfile.mkdtemp(prefix="jacs_agreement_v2_")
    password = secrets.token_urlsafe(32)
    demo_env = {
        "JACS_PRIVATE_KEY_PASSWORD": password,
        "JACS_KEYCHAIN_BACKEND": "disabled",
    }
    previous_env = {key: os.environ.get(key) for key in demo_env}
    os.environ.update(demo_env)

    try:
        print(f"Workspace: {base}")

        agent_a, a = create_agent("agent-a", base, password)
        agent_b, b = create_agent("agent-b", base, password)
        notary, n = create_agent("demo-notary", base, password)
        adversary, x = create_agent("agent-x", base, password)

        print("Cast:")
        print(f"  Agent A: {a['agent_id']}")
        print(f"  Agent B: {b['agent_id']}")
        print(f"  Notary : {n['agent_id']} (local demo label)")
        print(f"  Agent X: {x['agent_id']}")

        agreement_input = {
            "title": "Bounded refund authorization",
            "description": "Demo refund terms for agent signature inspection; no refund is authorized.",
            "terms": "Agent B may issue a refund up to $25 for order 123 after Agent A approval.",
            "termsFormat": "text/markdown",
            "status": "proposed",
            "parties": [
                {
                    "agentId": a["agent_id"],
                    "agentVersion": a["version"],
                    "agentType": "ai",
                    "role": "signer",
                    "displayName": "Agent A",
                },
                {
                    "agentId": b["agent_id"],
                    "agentVersion": b["version"],
                    "agentType": "ai",
                    "role": "signer",
                    "displayName": "Agent B",
                },
                {
                    "agentId": n["agent_id"],
                    "agentVersion": n["version"],
                    "agentType": "ai",
                    "role": "notary",
                    "displayName": "Local demo notary",
                },
            ],
            "signaturePolicy": {
                "partyQuorum": "all",
                "witnessRequired": 0,
                "notaryRequired": 1,
                "requiredAlgorithms": ["ring-Ed25519"],
                "minimumStrength": "classical",
            },
            "controllers": [a["agent_id"], b["agent_id"], n["agent_id"]],
            "owners": [a["agent_id"], b["agent_id"]],
        }

        print("\nCreate agreement")
        agreement = agent_a.create_agreement_v2(agreement_input)
        created = json.loads(agreement)
        print(f"  jacsId: {created['jacsId']}")
        print(f"  version: {created['jacsVersion']}")

        print("\nDialogue")
        statement_a = agent_a.sign_message({"forRecord": "Agent A proposes bounded refund terms."})
        statement_b = agent_b.sign_message({"forRecord": "Agent B accepts the bounded refund terms."})
        agreement = agent_a.apply_agreement_v2(
            agreement,
            {"type": "appendTranscript", "entry": doc_ref(statement_a)},
        )
        agreement = agent_b.apply_agreement_v2(
            agreement,
            {"type": "appendTranscript", "entry": doc_ref(statement_b)},
        )
        print("  transcript entries appended")

        print("\nAdversary checks")
        expect_rejected(
            "outsider mutation",
            "not a controller",
            lambda: adversary.apply_agreement_v2(
                agreement,
                {"type": "updateTerms", "terms": "Agent X rewrites the agreement."},
            ),
        )
        expect_rejected(
            "outsider signature",
            "not listed as a signer party",
            lambda: adversary.sign_agreement_v2(agreement, "signer"),
        )

        print("\nSignature inspection (no policy acceptance)")
        agreement = agent_a.sign_agreement_v2(agreement, "signer")
        agreement = agent_b.sign_agreement_v2(agreement, "signer")
        agreement = notary.sign_agreement_v2(agreement, "notary")

        report = notary.verify_agreement_v2(agreement)
        print(f"  mathematicalChecksValid: {report['mathematicalChecksValid']}")
        print(f"  valid: {report['valid']}")
        print(f"  policyAccepted: {report['policyAccepted']}")
        print(f"  overallScope: {report['overallScope']}")
        print(f"  status: {report['status']}")
        print(f"  expectedStatus: {report['expectedStatus']}")
        print(f"  signerCount: {report['signerCount']}")
        print(f"  notaryCount: {report['notaryCount']}")

        assert report["mathematicalChecksValid"] is True, report["errors"]
        assert report["errors"] == [], report
        assert_policy_unaccepted(report)
        assert report["expectedStatus"] == "final", report
        assert report["signerCount"] == 2, report
        assert report["notaryCount"] == 1, report
        print("  Counts and final status are structural diagnostics, not authority or human approval.")

        print("\nTamper checks")
        for label in ("transcript", "signature"):
            tampered = json.loads(agreement)
            if label == "transcript":
                tampered["transcript"].reverse()
            else:
                signature = tampered["agreementSignatures"][0]["signature"]
                encoded = signature["signature"]
                signature["signature"] = ("A" if encoded[0] != "A" else "B") + encoded[1:]
            # Raw edits invalidate the outer content hash. The native verifier
            # rejects these before it can return an inspection report.
            expect_rejected(
                f"{label} tampering",
                "Hashes don't match",
                lambda: notary.verify_agreement_v2(json.dumps(tampered)),
            )

        # A rejected document must not corrupt subsequent inspection.
        recovered = notary.verify_agreement_v2(agreement)
        assert recovered["mathematicalChecksValid"] is True, recovered
        assert_policy_unaccepted(recovered)
        print("  Original signatures still pass inspection; policy remains unaccepted.")

    finally:
        shutil.rmtree(base, ignore_errors=True)
        for key, previous in previous_env.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous


if __name__ == "__main__":
    main()
