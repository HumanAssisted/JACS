#!/usr/bin/env python3
"""
JACS Quickstart Example

This example demonstrates the simplified JACS API in under 2 minutes.

Usage:
    # First, create an agent (only needed once)
    python quickstart.py --create

    # Then run the example
    python quickstart.py
"""

import argparse
import sys
import os

# Add parent directory for development imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import jacs.simple as jacs


def create_agent():
    """Create a new JACS agent."""
    print("Creating a new JACS agent...")

    try:
        agent = jacs.create(name="Quickstart Agent")
        print(f"Agent created successfully!")
        print(f"  Agent ID: {agent.agent_id}")
        print(f"  Algorithm: {agent.algorithm}")
    except jacs.JacsError as e:
        print(f"Error creating agent: {e}")
        print("\nTry using the CLI instead:")
        print("  jacs create")
        sys.exit(1)


def main():
    """Main example demonstrating the simplified API."""
    print("=" * 60)
    print("JACS Quickstart Example")
    print("=" * 60)

    # Step 1: Load the agent
    print("\n1. Loading agent from config...")
    try:
        agent = jacs.load("./jacs.config.json")
        print(f"   Loaded agent: {agent.agent_id}")
    except jacs.ConfigError:
        print("   No agent found. Creating one first...")
        create_agent()
        agent = jacs.load("./jacs.config.json")

    # Step 2: Verify the agent's integrity
    print("\n2. Verifying agent integrity...")
    result = jacs.verify_self()
    if result.valid:
        print("   Agent verified successfully!")
    else:
        print(f"   Verification failed: {result.error}")
        sys.exit(1)

    # Step 3: Sign a message
    print("\n3. Signing a message...")
    message = "Hello, JACS! This message is cryptographically signed."
    signed = jacs.sign_message(message)
    print(f"   Document ID: {signed.document_id}")
    print(f"   Signer: {signed.signer_id}")
    print(f"   Signed at: {signed.signed_at}")

    # Step 4: Verify the signed message
    print("\n4. Verifying the signed message...")
    verify_result = jacs.verify(signed.raw_json)
    if verify_result.valid:
        print("   Signature verified!")
        print(f"   Signer ID: {verify_result.signer_id}")
    else:
        print(f"   Verification failed: {verify_result.error}")

    # Step 5: Display the signed document
    print("\n5. Signed document (truncated):")
    preview = signed.raw_json[:500] + "..." if len(signed.raw_json) > 500 else signed.raw_json
    print(f"   {preview}")

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)

    # Show next steps
    print("\nNext steps:")
    print("  - Sign a file:    jacs.sign_file('document.pdf')")
    print("  - Export agent:   jacs.export_agent()")
    print("  - Get public key: jacs.get_public_key()")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JACS Quickstart Example")
    parser.add_argument(
        "--create",
        action="store_true",
        help="Create a new agent before running the example"
    )
    args = parser.parse_args()

    if args.create:
        create_agent()
    else:
        main()
