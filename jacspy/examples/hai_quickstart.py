#!/usr/bin/env python3
"""HAI.ai Quickstart - Register your agent in 5 minutes.

This minimal example shows how to:
1. Test connection to HAI.ai
2. Register your JACS agent with HAI.ai

Prerequisites:
    1. Create a JACS agent first:
       python quickstart.py --create

    2. Install HAI dependencies:
       pip install httpx httpx-sse

    3. Get an API key from HAI.ai (https://hai.ai)

Usage:
    # Test connection
    python hai_quickstart.py --test

    # Register your agent
    export HAI_API_KEY=your-api-key
    python hai_quickstart.py
"""

import argparse
import os
import sys

# Add parent directory for development imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import jacs.simple as jacs
from jacs.hai import HaiClient


def main():
    """Minimal HAI.ai integration example."""
    parser = argparse.ArgumentParser(
        description="HAI.ai Quickstart Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--test", "-t",
        action="store_true",
        help="Only test connection, don't register",
    )
    parser.add_argument(
        "--url",
        default="https://hai.ai",
        help="HAI.ai server URL (default: https://hai.ai)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("HAI.ai Quickstart")
    print("=" * 60)

    # Step 1: Connect to HAI
    print(f"\n1. Connecting to {args.url}...")
    client = HaiClient()

    if client.testconnection(args.url):
        print("   ✓ Connected to HAI.ai")
    else:
        print("   ✗ Connection failed")
        sys.exit(1)

    if args.test:
        print("\nTest-only mode, exiting.")
        return

    # Step 2: Load your agent
    print("\n2. Loading JACS agent...")
    try:
        agent = jacs.load("./jacs.config.json")
        print(f"   ✓ Loaded agent: {agent.agent_id}")
    except jacs.ConfigError:
        print("   ✗ Agent config not found")
        print("\n   Create an agent first with:")
        print("     python quickstart.py --create")
        sys.exit(1)

    # Step 3: Get API key
    print("\n3. Getting API key...")
    api_key = os.environ.get("HAI_API_KEY")
    if not api_key:
        print("   ✗ HAI_API_KEY environment variable not set")
        print("\n   Set your API key with:")
        print("     export HAI_API_KEY=your-api-key-here")
        sys.exit(1)
    print("   ✓ API key loaded from environment")

    # Step 4: Register your agent
    print("\n4. Registering agent with HAI.ai...")
    try:
        result = client.register(args.url, api_key=api_key)
        print("   ✓ Agent registered!")
        print(f"\n   Agent ID: {result.agent_id}")
        print(f"   Registration ID: {result.registration_id}")
        print(f"   Registered at: {result.registered_at}")
    except Exception as e:
        print(f"   ✗ Registration failed: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("Success! Your agent is registered with HAI.ai")
    print("=" * 60)

    print("\nNext steps:")
    print("  - Run benchmarks:  python run_benchmark.py")
    print("  - Stream events:   python sse_client.py")
    print("  - Full example:    python register_with_hai.py")


if __name__ == "__main__":
    main()
