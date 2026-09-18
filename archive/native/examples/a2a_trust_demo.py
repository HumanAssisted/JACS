#!/usr/bin/env python3
"""
Multi-agent A2A trust verification demo -- zero setup.

Three agents interact via the A2A protocol:
  Agent A (JACS) -- Signs a task artifact and sends it
  Agent B (JACS) -- Receives, verifies, and countersigns with chain of custody
  Agent C (plain) -- Attempts to participate but is blocked by trust policy

Demonstrates:
  - A2A artifact signing with JACS provenance
  - Cross-agent verification and trust assessment
  - Chain of custody across multiple signers
  - Trust policy enforcement (verified rejects non-JACS, strict requires trust store)
  - Agent Card export and JACS extension detection

Run:
  python examples/a2a_trust_demo.py
"""

import json
import sys

from jacs.client import JacsClient
from jacs.a2a import JACSA2AIntegration


def main() -> None:
    # -- Step 1: Create JACS agents (A and B) -----------------------------------
    print("Step 1 -- Create agents")
    agent_a = JacsClient.ephemeral("ring-Ed25519")
    agent_b = JacsClient.ephemeral("ring-Ed25519")

    print(f"  Agent A (JACS) : {agent_a.agent_id}")
    print(f"  Agent B (JACS) : {agent_b.agent_id}")
    print("  Agent C (plain): no JACS identity -- standard A2A only")

    # -- Step 2: Agent A signs a task artifact ----------------------------------
    print("\nStep 2 -- Agent A signs a task artifact")
    task_payload = {
        "action": "classify",
        "input": "Analyze quarterly revenue data",
        "priority": "high",
    }

    signed_task = agent_a.sign_artifact(task_payload, "task")
    print(f"  Artifact ID : {signed_task.get('jacsId', 'N/A')}")
    print(f"  Type        : {signed_task.get('jacsType', 'N/A')}")
    sig = signed_task.get("jacsSignature", {})
    signer_id = sig.get("agentID", "unknown") if isinstance(sig, dict) else "unknown"
    print(f"  Signer      : {signer_id[:12]}...")

    # -- Step 3: Agent B verifies the artifact ----------------------------------
    print("\nStep 3 -- Agent B verifies the artifact from Agent A")
    a2a_b = JACSA2AIntegration(agent_b, trust_policy="verified")
    verify_result = a2a_b.verify_wrapped_artifact(signed_task, assess_trust=True)

    print(f"  Valid       : {verify_result.get('valid')}")
    signer = verify_result.get("signer_id", "unknown") or "unknown"
    print(f"  Signer ID   : {signer[:12]}...")
    trust = verify_result.get("trust", {})
    print(f"  Trust level : {trust.get('trust_level', 'N/A')}")
    print(f"  Allowed     : {trust.get('allowed', 'N/A')}")

    # -- Step 4: Agent B countersigns with chain of custody ---------------------
    print("\nStep 4 -- Agent B countersigns (chain of custody)")
    result_payload = {
        "action": "classify_result",
        "output": {"category": "financial", "confidence": 0.97},
        "parentTaskId": signed_task.get("jacsId"),
    }

    signed_result = agent_b.sign_artifact(
        result_payload, "result", parent_signatures=[signed_task]
    )
    print(f"  Result ID   : {signed_result.get('jacsId', 'N/A')}")
    parents = signed_result.get("jacsParentSignatures", [])
    print(f"  Parents     : {len(parents) if isinstance(parents, list) else 0}")
    sig_b = signed_result.get("jacsSignature", {})
    signer_b = sig_b.get("agentID", "unknown") if isinstance(sig_b, dict) else "unknown"
    print(f"  Signer      : {signer_b[:12]}...")

    # -- Step 5: Verify the full chain ------------------------------------------
    print("\nStep 5 -- Verify the full chain of custody")
    a2a_a = JACSA2AIntegration(agent_a, trust_policy="verified")
    chain_result = a2a_a.verify_wrapped_artifact(signed_result)

    print(f"  Chain valid            : {chain_result.get('valid')}")
    print(f"  Parent sigs valid      : {chain_result.get('parent_signatures_valid')}")
    parent_count = chain_result.get("parent_signatures_count", 0)
    print(f"  Parent sigs count      : {parent_count}")

    # -- Step 6: Agent C (non-JACS) is blocked by trust policy ------------------
    print("\nStep 6 -- Agent C (plain A2A, no JACS) tries to join")

    # Simulate Agent C's agent card -- a standard A2A card with no JACS extension
    agent_c_card = json.dumps({
        "name": "Agent C",
        "description": "A plain A2A agent without JACS",
        "version": "1.0",
        "protocolVersions": ["0.4.0"],
        "skills": [
            {"id": "chat", "name": "Chat", "description": "General chat", "tags": ["chat"]}
        ],
        "capabilities": {"streaming": True},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
    })

    # Agent B assesses Agent C under "verified" policy (default)
    assess_verified = a2a_b.assess_remote_agent(agent_c_card)
    print("  Verified policy:")
    print(f"    JACS registered : {assess_verified.get('jacs_registered')}")
    print(f"    Allowed         : {assess_verified.get('allowed')}")
    print(f"    Reason          : {assess_verified.get('reason', 'N/A')}")

    # Under "strict" policy, even Agent A would be rejected without trust store entry
    a2a_strict = JACSA2AIntegration(agent_b, trust_policy="strict")
    card_a = agent_a.export_agent_card()
    # export_agent_card returns an A2AAgentCard dataclass; convert to JSON string
    card_a_json = json.dumps({
        "name": card_a.name,
        "description": card_a.description,
        "version": card_a.version,
        "skills": [
            {"id": s.id, "name": s.name, "description": s.description, "tags": s.tags}
            for s in (card_a.skills or [])
        ],
        "capabilities": {
            "extensions": [
                {"uri": e.uri, "description": e.description, "required": e.required}
                for e in (card_a.capabilities.extensions if card_a.capabilities else [])
            ]
        } if card_a.capabilities else {},
    })
    assess_strict = a2a_strict.assess_remote_agent(card_a_json)
    print("  Strict policy (Agent A):")
    print(f"    JACS registered : {assess_strict.get('jacs_registered')}")
    print(f"    In trust store  : {assess_strict.get('in_trust_store')}")
    print(f"    Allowed         : {assess_strict.get('allowed')}")
    print(f"    Reason          : {assess_strict.get('reason', 'N/A')}")

    # -- Step 7: Export Agent Cards for A2A discovery ---------------------------
    print("\nStep 7 -- Export Agent Cards")
    card_agent_a = agent_a.export_agent_card()
    card_agent_b = agent_b.export_agent_card()

    print(f"  Agent A card: name=\"{card_agent_a.name}\", skills={len(card_agent_a.skills or [])}")
    print(f"  Agent B card: name=\"{card_agent_b.name}\", skills={len(card_agent_b.skills or [])}")

    has_jacs_ext_a = any(
        "jacs" in (e.uri or "")
        for e in (card_agent_a.capabilities.extensions if card_agent_a.capabilities else [])
    )
    has_jacs_ext_b = any(
        "jacs" in (e.uri or "")
        for e in (card_agent_b.capabilities.extensions if card_agent_b.capabilities else [])
    )
    print(f"  Both declare JACS extension: {has_jacs_ext_a and has_jacs_ext_b}")

    print("\nDone.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
