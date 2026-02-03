#!/usr/bin/env python3
"""HAI.ai Quickstart - Register your agent in 5 minutes.

This minimal example shows how to create a JACS agent and register it with HAI.ai
in ONE step using register_new_agent().

Prerequisites:
    1. Install HAI dependencies:
       uv pip install jacs[hai]
       # Or with pip: pip install jacs[hai]

    2. Get an API key from HAI.ai (https://hai.ai/developers)

Usage:
    # Test connection only
    python hai_quickstart.py --test

    # Create and register (uses HAI_API_KEY env var)
    export HAI_API_KEY=your-api-key
    python hai_quickstart.py

    # Or specify API key directly
    python hai_quickstart.py --api-key your-api-key
"""

import argparse
import os
import sys

# Add parent directory for development imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from jacs.hai import HaiClient, register_new_agent


def main():
    """Create and register an agent with HAI.ai."""
    parser = argparse.ArgumentParser(
        description="HAI.ai Quickstart - Create and register an agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--test", "-t",
        action="store_true",
        help="Only test connection, don't create/register",
    )
    parser.add_argument(
        "--url",
        default="https://hai.ai",
        help="HAI.ai server URL (default: https://hai.ai)",
    )
    parser.add_argument(
        "--api-key",
        help="API key (or set HAI_API_KEY env var)",
    )
    parser.add_argument(
        "--name",
        default="My Agent",
        help="Name for your agent (default: 'My Agent')",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("HAI.ai Quickstart")
    print("=" * 60)

    # Test connection only
    if args.test:
        print(f"\nTesting connection to {args.url}...")
        client = HaiClient()
        if client.testconnection(args.url):
            print("Connected to HAI.ai")
        else:
            print("Connection failed")
            sys.exit(1)
        return

    # Create and register in ONE step
    print(f"\nCreating and registering agent '{args.name}'...")

    try:
        result = register_new_agent(
            name=args.name,
            hai_url=args.url,
            api_key=args.api_key,  # Falls back to HAI_API_KEY env var
        )
        print(f"\nAgent registered!")
        print(f"  Agent ID: {result.agent_id}")
        print(f"  Registration ID: {result.registration_id}")
        print(f"  Config saved to: ./jacs.config.json")

    except Exception as e:
        print(f"\nRegistration failed: {e}")
        if "HAI_API_KEY" in str(e) or "api_key" in str(e).lower():
            print("\nSet your API key:")
            print("  export HAI_API_KEY=your-api-key")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("Success! Your agent is registered with HAI.ai")
    print("=" * 60)

    print("\nNext steps:")
    print("  - Run benchmarks:  python run_benchmark.py")
    print("  - Stream events:   python sse_client.py")


if __name__ == "__main__":
    main()
