#!/usr/bin/env python3
"""Agreement v2 golden workflow: two signers, HAI notary, outsider rejected.

Run from the repository root after installing/building the Python package:

    python examples/agreement_v2_three_party.py
"""

import json
import os
import shutil
import tempfile
from pathlib import Path

from jacs import SimpleAgent


PASSWORD = "AgreementV2Demo!2026"


def create_agent(name: str, base: str, agent_type: str = "ai"):
    key_dir = Path(base) / f"{name}_keys"
    config_path = Path(base) / f"{name}.config.json"
    agent, info = SimpleAgent.create_agent(
        name=name,
        password=PASSWORD,
        algorithm="ring-Ed25519",
        data_directory=str(Path(base) / "shared_data"),
        key_directory=str(key_dir),
        config_path=str(config_path),
        agent_type=agent_type,
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


def expect_rejected(label: str, fn) -> None:
    try:
        fn()
    except Exception as exc:
        print(f"  rejected {label}: {str(exc).splitlines()[0]}")
        return
    raise AssertionError(f"expected rejection: {label}")


def main() -> None:
    base = tempfile.mkdtemp(prefix="jacs_agreement_v2_")
    os.environ["JACS_PRIVATE_KEY_PASSWORD"] = PASSWORD

    try:
        print(f"Workspace: {base}")

        agent_a, a = create_agent("agent-a", base)
        agent_b, b = create_agent("agent-b", base, agent_type="human")
        hai, h = create_agent("hai-notary", base)
        adversary, x = create_agent("agent-x", base)

        print("Cast:")
        print(f"  Agent A: {a['agent_id']}")
        print(f"  Agent B: {b['agent_id']}")
        print(f"  HAI    : {h['agent_id']}")
        print(f"  Agent X: {x['agent_id']}")

        agreement_input = {
            "title": "Bounded refund authorization",
            "description": "Agent A and Agent B agree on a bounded customer refund; HAI notarizes the final state.",
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
                    "agentType": "human",
                    "role": "signer",
                    "displayName": "Agent B",
                },
                {
                    "agentId": h["agent_id"],
                    "agentVersion": h["version"],
                    "agentType": "ai",
                    "role": "notary",
                    "displayName": "HAI",
                },
            ],
            "signaturePolicy": {
                "partyQuorum": "all",
                "witnessRequired": 0,
                "notaryRequired": 1,
                "requiredAlgorithms": ["ring-Ed25519"],
                "minimumStrength": "classical",
            },
            "controllers": [a["agent_id"], b["agent_id"], h["agent_id"]],
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
            lambda: adversary.apply_agreement_v2(
                agreement,
                {"type": "updateTerms", "terms": "Agent X rewrites the agreement."},
            ),
        )
        expect_rejected(
            "outsider signature",
            lambda: adversary.sign_agreement_v2(agreement, "signer"),
        )

        print("\nFinalization")
        agreement = agent_a.sign_agreement_v2(agreement, "signer")
        agreement = agent_b.sign_agreement_v2(agreement, "signer")
        agreement = hai.sign_agreement_v2(agreement, "notary")

        report = hai.verify_agreement_v2(agreement)
        print(f"  valid: {report['valid']}")
        print(f"  status: {report['status']}")
        print(f"  expectedStatus: {report['expectedStatus']}")
        print(f"  signerCount: {report['signerCount']}")
        print(f"  notaryCount: {report['notaryCount']}")

        if not report["valid"]:
            raise AssertionError(report["errors"])

    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
