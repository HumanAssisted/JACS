#!/usr/bin/env python3
"""
JACS P2P Key Exchange Example

Demonstrates peer-to-peer trust establishment between two JACS agents.
This is how agents can verify each other's signatures without a
central authority.

The workflow:
1. Alice creates an agent and exports her agent document
2. Bob creates an agent and exports his agent document
3. Alice and Bob exchange agent documents (out of band)
4. Alice trusts Bob's agent document
5. Bob trusts Alice's agent document
6. Now they can verify each other's signatures

Usage:
    # Run as Alice
    python p2p_exchange.py alice

    # Run as Bob
    python p2p_exchange.py bob

    # Simulate full exchange
    python p2p_exchange.py demo
"""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

# Add parent directory for development imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import jacs.simple as jacs


def setup_agent(name: str, work_dir: str) -> jacs.AgentInfo:
    """Set up an agent in a working directory.

    Args:
        name: Agent name (e.g., "alice", "bob")
        work_dir: Directory to store agent files

    Returns:
        AgentInfo for the created/loaded agent
    """
    config_path = os.path.join(work_dir, "jacs.config.json")

    # Check if agent already exists
    if os.path.exists(config_path):
        print(f"[{name}] Loading existing agent from {work_dir}")
        return jacs.load(config_path)

    print(f"[{name}] Creating new agent in {work_dir}")

    # For now, we need to use CLI or manual creation
    # This is a simplified example showing the workflow
    raise jacs.JacsError(
        f"Please create an agent first:\n"
        f"  cd {work_dir} && jacs create"
    )


def export_for_sharing(name: str) -> str:
    """Export the agent document for sharing with peers.

    Args:
        name: Agent name for logging

    Returns:
        The agent document JSON string
    """
    print(f"[{name}] Exporting agent document for sharing...")

    agent_doc = jacs.export_agent()
    agent_info = jacs.get_agent_info()

    print(f"[{name}] Agent ID: {agent_info.agent_id}")
    print(f"[{name}] Document ready to share ({len(agent_doc)} bytes)")

    return agent_doc


def trust_peer(my_name: str, peer_name: str, peer_agent_doc: str):
    """Trust a peer's agent document.

    Args:
        my_name: This agent's name for logging
        peer_name: Peer's name for logging
        peer_agent_doc: The peer's agent document JSON
    """
    print(f"[{my_name}] Trusting {peer_name}'s agent...")

    # Parse peer document to get their ID
    peer_data = json.loads(peer_agent_doc)
    peer_id = peer_data.get("jacsId", "unknown")

    print(f"[{my_name}] Peer agent ID: {peer_id}")

    # In a real implementation, this would call the trust store
    # For now, we just verify the document is valid
    result = jacs.verify(peer_agent_doc)

    if result.valid:
        print(f"[{my_name}] Peer document verified - signature valid")
        print(f"[{my_name}] {peer_name} is now trusted")
    else:
        print(f"[{my_name}] Warning: Could not verify peer document: {result.error}")
        print(f"[{my_name}] Trusting anyway (in production, you might reject this)")


def sign_message_for_peer(my_name: str, peer_name: str, message: str) -> str:
    """Sign a message to send to a peer.

    Args:
        my_name: This agent's name for logging
        peer_name: Recipient's name for logging
        message: Message to sign

    Returns:
        Signed document JSON string
    """
    print(f"\n[{my_name}] Signing message for {peer_name}...")
    print(f"[{my_name}] Message: {message}")

    signed = jacs.sign_message(message)

    print(f"[{my_name}] Document ID: {signed.document_id}")
    print(f"[{my_name}] Signed at: {signed.signed_at}")

    return signed.raw_json


def verify_message_from_peer(
    my_name: str,
    peer_name: str,
    signed_doc: str
) -> bool:
    """Verify a signed message from a peer.

    Args:
        my_name: This agent's name for logging
        peer_name: Sender's name for logging
        signed_doc: The signed document JSON

    Returns:
        True if verification succeeded
    """
    print(f"\n[{my_name}] Verifying message from {peer_name}...")

    result = jacs.verify(signed_doc)

    if result.valid:
        print(f"[{my_name}] Signature VALID")
        print(f"[{my_name}] Signer: {result.signer_id}")
        print(f"[{my_name}] Timestamp: {result.timestamp}")

        # Extract the message content
        doc_data = json.loads(signed_doc)
        payload = doc_data.get("jacsDocument", {})
        content = payload.get("content", payload)
        print(f"[{my_name}] Message content: {content}")

        return True
    else:
        print(f"[{my_name}] Signature INVALID: {result.error}")
        return False


def run_demo():
    """Run a complete P2P exchange demonstration."""
    print("=" * 60)
    print("JACS P2P Key Exchange Demo")
    print("=" * 60)

    # Create temporary directories for Alice and Bob
    with tempfile.TemporaryDirectory() as alice_dir:
        with tempfile.TemporaryDirectory() as bob_dir:
            print(f"\nAlice's directory: {alice_dir}")
            print(f"Bob's directory: {bob_dir}")

            # For the demo, we'll use the same agent for both
            # In reality, each would have their own agent
            print("\n--- Setup Phase ---")
            print("(In reality, Alice and Bob would each run 'jacs create')")

            # Check if we have an agent loaded
            try:
                jacs.load("./jacs.config.json")
                agent_info = jacs.get_agent_info()
                print(f"\nUsing existing agent: {agent_info.agent_id}")
            except jacs.ConfigError:
                print("\nNo agent found. Please create one first:")
                print("  jacs create")
                sys.exit(1)

            # Export agent documents
            print("\n--- Export Phase ---")
            alice_doc = export_for_sharing("Alice")
            bob_doc = export_for_sharing("Bob")

            # Trust establishment
            print("\n--- Trust Phase ---")
            trust_peer("Alice", "Bob", bob_doc)
            trust_peer("Bob", "Alice", alice_doc)

            # Message exchange
            print("\n--- Message Exchange ---")

            # Alice sends to Bob
            alice_message = "Hello Bob! This is Alice."
            signed_from_alice = sign_message_for_peer("Alice", "Bob", alice_message)
            verify_message_from_peer("Bob", "Alice", signed_from_alice)

            # Bob sends to Alice
            bob_message = "Hi Alice! Got your message."
            signed_from_bob = sign_message_for_peer("Bob", "Alice", bob_message)
            verify_message_from_peer("Alice", "Bob", signed_from_bob)

            print("\n" + "=" * 60)
            print("P2P Exchange Demo Complete!")
            print("=" * 60)
            print("\nKey takeaways:")
            print("1. Each agent has a unique cryptographic identity")
            print("2. Agent documents can be exchanged out-of-band")
            print("3. Once trusted, signatures can be verified")
            print("4. No central authority required")


def main():
    parser = argparse.ArgumentParser(
        description="JACS P2P Key Exchange Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "mode",
        choices=["alice", "bob", "demo"],
        help="Run as alice, bob, or demo mode"
    )
    parser.add_argument(
        "-c", "--config",
        default="./jacs.config.json",
        help="Path to JACS config file (default: ./jacs.config.json)"
    )

    args = parser.parse_args()

    if args.mode == "demo":
        run_demo()
    elif args.mode == "alice":
        print("Running as Alice...")
        jacs.load(args.config)
        alice_doc = export_for_sharing("Alice")
        print("\nShare this document with Bob:")
        print(alice_doc[:200] + "...")
        print(f"\n(Full document: {len(alice_doc)} bytes)")
    elif args.mode == "bob":
        print("Running as Bob...")
        jacs.load(args.config)
        bob_doc = export_for_sharing("Bob")
        print("\nShare this document with Alice:")
        print(bob_doc[:200] + "...")
        print(f"\n(Full document: {len(bob_doc)} bytes)")


if __name__ == "__main__":
    main()
