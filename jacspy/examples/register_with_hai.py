#!/usr/bin/env python3
"""
HAI.ai Agent Registration Example

This example demonstrates how to register a JACS agent with HAI.ai platform.

Prerequisites:
    1. Create a JACS agent first:
       python quickstart.py --create

    2. Install HAI dependencies:
       pip install httpx httpx-sse

    3. Get an API key from HAI.ai (https://hai.ai)

Usage:
    # Test connection first
    python register_with_hai.py --test https://hai.ai

    # Register your agent
    python register_with_hai.py https://hai.ai --api-key YOUR_API_KEY

    # Or use environment variable
    export HAI_API_KEY=your-api-key
    python register_with_hai.py https://hai.ai
"""

import argparse
import os
import sys

# Add parent directory for development imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import jacs.simple as jacs
from jacs.hai import (
    HaiClient,
    HaiError,
    RegistrationError,
    HaiConnectionError,
    AuthenticationError,
)


def test_connection(hai_url: str) -> bool:
    """Test connectivity to HAI.ai."""
    print(f"Testing connection to {hai_url}...")

    hai = HaiClient()
    if hai.testconnection(hai_url):
        print("  Connection successful!")
        return True
    else:
        print("  Connection failed. Check the URL and your network.")
        return False


def register_agent(hai_url: str, api_key: str = None):
    """Register the loaded JACS agent with HAI.ai."""
    print("\nRegistering agent with HAI.ai...")

    hai = HaiClient()

    try:
        result = hai.register(hai_url, api_key=api_key)

        print("\nRegistration successful!")
        print(f"  Agent ID: {result.agent_id}")
        print(f"  Registration ID: {result.registration_id}")
        print(f"  Registered at: {result.registered_at}")

        if result.hai_signature:
            print(f"  HAI Signature: {result.hai_signature[:50]}...")

        if result.capabilities:
            print(f"  Capabilities: {', '.join(result.capabilities)}")

        return result

    except AuthenticationError as e:
        print(f"\nAuthentication failed: {e}")
        print("  Make sure your API key is valid.")
        sys.exit(1)

    except RegistrationError as e:
        print(f"\nRegistration failed: {e}")
        if e.response_data:
            print(f"  Details: {e.response_data}")
        sys.exit(1)

    except HaiConnectionError as e:
        print(f"\nConnection error: {e}")
        print("  Check your network and the HAI.ai URL.")
        sys.exit(1)

    except HaiError as e:
        print(f"\nError: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Register a JACS agent with HAI.ai",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "hai_url",
        nargs="?",
        default="https://hai.ai",
        help="HAI.ai server URL (default: https://hai.ai)",
    )
    parser.add_argument(
        "--api-key", "-k",
        help="HAI.ai API key (or set HAI_API_KEY env var)",
    )
    parser.add_argument(
        "--config", "-c",
        default="./jacs.config.json",
        help="Path to JACS config file (default: ./jacs.config.json)",
    )
    parser.add_argument(
        "--test", "-t",
        action="store_true",
        help="Only test connection, don't register",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("HAI.ai Agent Registration")
    print("=" * 60)

    # Test connection first
    if not test_connection(args.hai_url):
        sys.exit(1)

    if args.test:
        print("\nTest-only mode, exiting.")
        return

    # Load JACS agent
    print(f"\nLoading JACS agent from {args.config}...")
    try:
        agent_info = jacs.load(args.config)
        print(f"  Agent ID: {agent_info.agent_id}")
        print(f"  Algorithm: {agent_info.algorithm}")
    except jacs.ConfigError as e:
        print(f"\nError: {e}")
        print("\nCreate an agent first with:")
        print("  python quickstart.py --create")
        sys.exit(1)

    # Get API key
    api_key = args.api_key or os.environ.get("HAI_API_KEY")
    if not api_key:
        print("\nWarning: No API key provided.")
        print("  Set HAI_API_KEY environment variable or use --api-key")
        print("  Some operations may require authentication.")

    # Register
    register_agent(args.hai_url, api_key)

    print("\n" + "=" * 60)
    print("Registration complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("  - Run benchmarks: python run_benchmark.py")
    print("  - Connect to event stream: see examples/sse_client.py")


if __name__ == "__main__":
    main()
