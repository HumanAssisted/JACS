#!/usr/bin/env python3
"""
JACS Quickstart Example

Sign it. Prove it. This example gets you signing in 3 lines.

Usage:
    python quickstart.py
    python quickstart.py --advanced   # Load from config file instead
"""

import argparse
import sys
import os

# Add parent directory for development imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import jacs.simple as jacs


def main():
    """Zero-config quickstart -- no config file, no setup."""
    print("=" * 60)
    print("JACS Quickstart")
    print("=" * 60)

    # Step 1: One call creates an ephemeral agent with keys in memory
    print("\n1. Creating ephemeral agent...")
    info = jacs.quickstart()
    print(f"   Agent ID: {info.agent_id}")
    print(f"   Algorithm: {info.algorithm}")

    # Step 2: Sign a message
    print("\n2. Signing a message...")
    signed = jacs.sign_message({"hello": "world", "action": "approve"})
    print(f"   Document ID: {signed.document_id}")
    print(f"   Signer: {signed.signer_id}")
    print(f"   Signed at: {signed.signed_at}")

    # Step 3: Verify it
    print("\n3. Verifying the signed message...")
    result = jacs.verify(signed.raw_json)
    if result.valid:
        print("   Signature verified!")
        print(f"   Signer ID: {result.signer_id}")
    else:
        print(f"   Verification failed: {result.error}")

    print("\n" + "=" * 60)
    print("Done. Three lines to sign and verify.")
    print("=" * 60)

    print("\nNext steps:")
    print("  - Sign a file:    jacs.sign_file('document.pdf')")
    print("  - Export agent:   jacs.export_agent()")
    print("  - Get public key: jacs.get_public_key()")


def advanced():
    """Load a persistent agent from a config file."""
    print("=" * 60)
    print("JACS Advanced Example (config file)")
    print("=" * 60)

    # Step 1: Load the agent
    print("\n1. Loading agent from config...")
    try:
        agent = jacs.load("./jacs.config.json")
        print(f"   Loaded agent: {agent.agent_id}")
    except jacs.ConfigError:
        print("   No agent found. Creating one first...")
        jacs.create(name="Quickstart Agent")
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

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JACS Quickstart Example")
    parser.add_argument(
        "--advanced",
        action="store_true",
        help="Load a persistent agent from config instead of using quickstart()"
    )
    args = parser.parse_args()

    if args.advanced:
        advanced()
    else:
        main()
