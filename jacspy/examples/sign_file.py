#!/usr/bin/env python3
"""
JACS File Signing Example

Demonstrates how to sign files with JACS, including:
- Signing with hash reference (default)
- Signing with embedded content
- Verifying signed files

Usage:
    # Sign a file with hash reference
    python sign_file.py document.pdf

    # Sign with embedded content
    python sign_file.py document.pdf --embed

    # Verify a signed file
    python sign_file.py --verify signed_document.json
"""

import argparse
import json
import os
import sys

# Add parent directory for development imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import jacs.simple as jacs


def sign_file(file_path: str, embed: bool = False, output: str = None):
    """Sign a file and save the signed document.

    Args:
        file_path: Path to the file to sign
        embed: If True, embed the file content in the document
        output: Output path for the signed document (optional)
    """
    print(f"Signing file: {file_path}")
    print(f"Embed content: {embed}")

    # Check file exists
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        sys.exit(1)

    # Load agent
    try:
        agent = jacs.load()
        print(f"Agent loaded: {agent.agent_id}")
    except jacs.ConfigError as e:
        print(f"Error: {e}")
        print("Run 'jacs create' to create an agent first.")
        sys.exit(1)

    # Sign the file
    try:
        signed = jacs.sign_file(file_path, embed=embed)
        print(f"\nFile signed successfully!")
        print(f"  Document ID: {signed.document_id}")
        print(f"  Signer: {signed.signer_id}")
        print(f"  Content hash: {signed.content_hash}")

        if signed.attachments:
            att = signed.attachments[0]
            print(f"\n  Attachment:")
            print(f"    Filename: {att.filename}")
            print(f"    MIME type: {att.mime_type}")
            print(f"    File hash: {att.content_hash}")
            print(f"    Embedded: {'Yes' if att.content else 'No'}")

        # Determine output path
        if output is None:
            base_name = os.path.splitext(file_path)[0]
            output = f"{base_name}.signed.json"

        # Save the signed document
        with open(output, 'w') as f:
            f.write(signed.raw_json)

        print(f"\nSigned document saved to: {output}")

        return signed

    except jacs.SigningError as e:
        print(f"Error signing file: {e}")
        sys.exit(1)


def verify_file(signed_path: str):
    """Verify a signed file document.

    Args:
        signed_path: Path to the signed document JSON
    """
    print(f"Verifying signed document: {signed_path}")

    # Check file exists
    if not os.path.exists(signed_path):
        print(f"Error: File not found: {signed_path}")
        sys.exit(1)

    # Load agent
    try:
        agent = jacs.load()
        print(f"Agent loaded: {agent.agent_id}")
    except jacs.ConfigError as e:
        print(f"Error: {e}")
        print("Run 'jacs create' to create an agent first.")
        sys.exit(1)

    # Read the signed document
    with open(signed_path, 'r') as f:
        signed_json = f.read()

    # Verify
    result = jacs.verify(signed_json)

    print(f"\nVerification result:")
    print(f"  Valid: {result.valid}")

    if result.valid:
        print(f"  Signer ID: {result.signer_id}")
        print(f"  Public key hash: {result.signer_public_key_hash}")
        print(f"  Signature valid: {result.signature_valid}")
        print(f"  Hash valid: {result.content_hash_valid}")
        print(f"  Signed at: {result.timestamp}")

        # Parse document to show file info
        doc = json.loads(signed_json)
        files = doc.get("jacsFiles", [])
        if files:
            print(f"\n  Signed files:")
            for f in files:
                print(f"    - {f.get('filename')}")
                print(f"      Hash: {f.get('sha256', 'N/A')[:32]}...")
                print(f"      MIME: {f.get('mimeType', 'unknown')}")

        print("\n[OK] Document is authentic and unmodified.")
    else:
        print(f"  Error: {result.error}")
        print("\n[FAIL] Document verification failed!")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="JACS File Signing Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Sign a PDF file
    python sign_file.py contract.pdf

    # Sign and embed the file content
    python sign_file.py image.png --embed

    # Specify output file
    python sign_file.py document.txt -o signed.json

    # Verify a signed document
    python sign_file.py --verify signed.json
        """
    )

    parser.add_argument(
        "file",
        help="File to sign (or signed document to verify with --verify)"
    )
    parser.add_argument(
        "--embed",
        action="store_true",
        help="Embed the file content in the signed document"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output path for signed document"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify a signed document instead of signing"
    )
    parser.add_argument(
        "-c", "--config",
        default="./jacs.config.json",
        help="Path to JACS config file (default: ./jacs.config.json)"
    )

    args = parser.parse_args()

    # Override default config if specified
    if args.config != "./jacs.config.json":
        os.environ["JACS_CONFIG"] = args.config

    if args.verify:
        verify_file(args.file)
    else:
        sign_file(args.file, embed=args.embed, output=args.output)


if __name__ == "__main__":
    main()
