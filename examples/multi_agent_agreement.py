#!/usr/bin/env python3
"""Multi-agent agreement with cryptographic proof -- zero setup.

Three agents negotiate and co-sign a deployment proposal using JACS.
Demonstrates quorum (2-of-3), timeout, independent verification,
and a full crypto proof chain.

Run:
    python examples/multi_agent_agreement.py
"""

import json
import os
import shutil
import tempfile
from datetime import datetime, timedelta, timezone

from jacs.client import JacsClient

DEMO_PASSWORD = "Demo!Str0ng#Pass42"


def create_agent(name: str, base: str) -> JacsClient:
    """Create a persistent agent in a shared workspace."""
    keys_dir = os.path.join(base, f"{name}_keys")
    os.makedirs(keys_dir, exist_ok=True)
    cfg = os.path.join(base, f"{name}.config.json")

    # Write a config that uses agent-specific keys but shared data dir
    from jacs import SimpleAgent
    agent, info = SimpleAgent.create_agent(
        name=name,
        password=DEMO_PASSWORD,
        algorithm="ring-Ed25519",
        data_directory=os.path.join(base, "shared_data"),
        key_directory=keys_dir,
        config_path=cfg,
    )

    # Load through JacsClient for the high-level API
    client = JacsClient(config_path=cfg)
    print(f"  {name}: {client.agent_id}")
    return client


def main() -> None:
    base = tempfile.mkdtemp(prefix="jacs_demo_")
    os.environ["JACS_PRIVATE_KEY_PASSWORD"] = DEMO_PASSWORD
    print(f"Working directory: {base}\n")

    # -- Step 1: Create three agents -----------------------------------------
    print("Step 1 -- Create agents")
    alice = create_agent("alice", base)
    bob = create_agent("bob", base)
    mediator = create_agent("mediator", base)

    # -- Step 2: Alice proposes an agreement ----------------------------------
    print("\nStep 2 -- Alice proposes an agreement")
    proposal = {
        "proposal": "Deploy model v2 to production",
        "conditions": [
            "passes safety audit",
            "approved by 2 of 3 signers",
        ],
    }
    deadline = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    agreement = alice.create_agreement(
        document=proposal,
        agent_ids=[alice.agent_id, bob.agent_id, mediator.agent_id],
        question="Do you approve deployment of model v2?",
        context="Production rollout pending safety audit sign-off.",
        quorum=2,
        timeout=deadline,
    )
    print(f"  Agreement ID : {agreement.document_id}")
    print(f"  Quorum       : 2 of 3")
    print(f"  Deadline     : {deadline}")

    # -- Step 3: Alice signs --------------------------------------------------
    print("\nStep 3 -- Alice signs")
    agreement = alice.sign_agreement(agreement)
    print(f"  Signed by Alice ({alice.agent_id[:12]}...)")

    # -- Step 4: Bob co-signs -------------------------------------------------
    print("\nStep 4 -- Bob co-signs")
    agreement = bob.sign_agreement(agreement)
    print(f"  Signed by Bob   ({bob.agent_id[:12]}...)")

    # -- Step 5: Mediator countersigns ----------------------------------------
    print("\nStep 5 -- Mediator countersigns")
    agreement = mediator.sign_agreement(agreement)
    print(f"  Signed by Mediator ({mediator.agent_id[:12]}...)")

    # -- Step 6: Check agreement status ---------------------------------------
    print("\nStep 6 -- Agreement status")
    status = alice.check_agreement(agreement)
    print(f"  Complete : {status.complete}")
    print(f"  Pending  : {status.pending}")
    for s in status.signers:
        label = "signed" if s.signed else "pending"
        print(f"    {s.agent_id[:12]}... {label}" +
              (f"  at {s.signed_at}" if s.signed_at else ""))

    # -- Step 7: Independent verification -------------------------------------
    print("\nStep 7 -- Independent verification")
    for name, client in [("Alice", alice), ("Bob", bob), ("Mediator", mediator)]:
        result = client.verify(agreement.raw_json)
        print(f"  {name} verifies: valid={result.valid}")

    # -- Cleanup --------------------------------------------------------------
    shutil.rmtree(base, ignore_errors=True)
    print(f"\nDone. Temp files cleaned up.")


if __name__ == "__main__":
    main()
