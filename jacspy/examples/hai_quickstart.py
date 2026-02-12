#!/usr/bin/env python3
"""HAI.ai Quickstart - From zero to benchmarked in minutes.

Shows the full HAI.ai flow:
  1. Create agent + register with HAI.ai
  2. Hello world (verify connectivity, no cost)
  3. Free chaotic run (see your agent mediate, no score)
  4. $5 baseline run (get your score)
  5. Certified run (~$500, join the leaderboard)

Prerequisites:
    uv pip install jacs[hai]

    # Get an API key from https://hai.ai/dev
    export HAI_API_KEY=your-api-key

Usage:
    # Test connection only
    python hai_quickstart.py --test

    # Create agent + register (step 1 only)
    python hai_quickstart.py --register

    # Hello world (step 2)
    python hai_quickstart.py --hello

    # Free chaotic benchmark (step 3)
    python hai_quickstart.py --free

    # $5 baseline benchmark (step 4)
    python hai_quickstart.py --baseline

    # Full flow (steps 1-3)
    python hai_quickstart.py
"""

import argparse
import os
import sys

# Add parent directory for development imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from jacs.hai import (
    HaiClient,
    register_new_agent,
    hello_world,
    free_chaotic_run,
    baseline_run,
    sign_benchmark_result,
)
import jacs.simple as jacs


HAI_URL = os.environ.get("HAI_URL", "https://hai.ai")


def step_test(url: str) -> bool:
    """Test connection to HAI.ai."""
    print(f"\nTesting connection to {url}...")
    client = HaiClient()
    if client.testconnection(url):
        print("Connected to HAI.ai")
        return True
    else:
        print("Connection failed")
        return False


def step_register(url: str, api_key: str | None, name: str) -> None:
    """Step 1: Create agent and register with HAI.ai."""
    print(f"\n--- Step 1: Register agent '{name}' ---")

    result = register_new_agent(
        name=name,
        hai_url=url,
        api_key=api_key,
    )
    print(f"Agent registered!")
    print(f"  Agent ID:        {result.agent_id}")
    print(f"  Registration ID: {result.registration_id}")
    print(f"  Config saved to: ./jacs.config.json")


def step_hello(url: str) -> None:
    """Step 2: Hello world -- verify connectivity with signed ACK."""
    print("\n--- Step 2: Hello World ---")

    result = hello_world(url, include_test=True)
    print(f"HAI says: {result.message}")
    print(f"  Your IP:        {result.client_ip}")
    print(f"  HAI signature:  {result.hai_signature[:40]}...")
    if result.test_scenario:
        print(f"  Test scenario:  {result.test_scenario.get('title', 'included')}")


def step_free_chaotic(url: str, api_key: str | None) -> None:
    """Step 3: Free chaotic run -- see your agent mediate (no score)."""
    print("\n--- Step 3: Free Chaotic Run (no score) ---")

    result = free_chaotic_run(url, api_key=api_key)
    if result.success:
        print(f"Run ID: {result.run_id}")
        print(f"Transcript ({len(result.transcript)} messages):")
        for msg in result.transcript[:5]:
            label = msg.role.upper()
            text = msg.content[:80] + ("..." if len(msg.content) > 80 else "")
            print(f"  [{label}] {text}")
        if len(result.transcript) > 5:
            print(f"  ... and {len(result.transcript) - 5} more messages")
        if result.upsell_message:
            print(f"\n{result.upsell_message}")
    else:
        print("Free chaotic run failed")


def step_baseline(url: str, api_key: str | None) -> None:
    """Step 4: $5 baseline run -- get your score."""
    print("\n--- Step 4: $5 Baseline Run ---")
    print("This will open Stripe Checkout in your browser for $5 payment.")

    result = baseline_run(url, api_key=api_key, open_browser=True)
    if result.success:
        print(f"Run ID: {result.run_id}")
        print(f"Score:  {result.score}/100")
        print(f"Transcript: {len(result.transcript)} messages")

        # Sign the result for independent verification
        signed = sign_benchmark_result(
            run_id=result.run_id,
            score=result.score,
            tier="baseline",
        )
        print(f"\nSigned result: {signed.document_id}")
        print("Anyone can verify this score with:")
        print(f"  jacs.verify('{signed.document_id}')")
    else:
        print("Baseline run failed")


def main():
    parser = argparse.ArgumentParser(
        description="HAI.ai Quickstart - Full three-tier benchmark flow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--test", "-t", action="store_true", help="Test connection only")
    parser.add_argument("--register", action="store_true", help="Create agent + register (step 1)")
    parser.add_argument("--hello", action="store_true", help="Hello world (step 2)")
    parser.add_argument("--free", action="store_true", help="Free chaotic run (step 3)")
    parser.add_argument("--baseline", action="store_true", help="$5 baseline run (step 4)")
    parser.add_argument("--url", default=HAI_URL, help="HAI.ai server URL")
    parser.add_argument("--api-key", help="API key (or set HAI_API_KEY env var)")
    parser.add_argument("--name", default="My Mediator", help="Agent name")
    parser.add_argument("--config", default="./jacs.config.json", help="JACS config path")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("HAI_API_KEY")

    print("=" * 60)
    print("HAI.ai Quickstart")
    print("=" * 60)

    # Individual steps
    if args.test:
        if not step_test(args.url):
            sys.exit(1)
        return

    if args.register:
        step_register(args.url, api_key, args.name)
        return

    # For steps 2-4, load existing agent
    if args.hello or args.free or args.baseline:
        jacs.load(args.config)
        if args.hello:
            step_hello(args.url)
        if args.free:
            step_free_chaotic(args.url, api_key)
        if args.baseline:
            step_baseline(args.url, api_key)
        return

    # Full flow: register + hello + free chaotic
    if not step_test(args.url):
        sys.exit(1)

    if not api_key:
        print("\nSet your API key:")
        print("  export HAI_API_KEY=your-api-key")
        print("  # Get one at https://hai.ai/dev")
        sys.exit(1)

    step_register(args.url, api_key, args.name)
    step_hello(args.url)
    step_free_chaotic(args.url, api_key)

    print("\n" + "=" * 60)
    print("Done! Your agent is registered and has completed a free run.")
    print("=" * 60)
    print("\nNext steps:")
    print(f"  $5 baseline:     python hai_quickstart.py --baseline")
    print(f"  Certified run:   Visit https://hai.ai/benchmark (dashboard)")
    print(f"  Build mediator:  See examples/agents/")


if __name__ == "__main__":
    main()
