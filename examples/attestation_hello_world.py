#!/usr/bin/env python3
"""Attestation hello world -- create and verify your first attestation.

Demonstrates the core attestation flow: sign a document, attest WHY it is
trustworthy, then verify the attestation. Uses an ephemeral agent (no files
on disk) for the simplest possible setup.

Run:
    pip install jacs[attestation]
    python examples/attestation_hello_world.py
"""

import hashlib
import json
from jacs.client import JacsClient

# 1. Create an ephemeral agent (in-memory keys, no files)
client = JacsClient.ephemeral(algorithm="ed25519")

# 2. Sign a document
signed = client.sign_message({"action": "approve", "amount": 100})
print(f"Signed document: {signed.document_id}")

# 3. Attest WHY this document is trustworthy
content_hash = hashlib.sha256(signed.raw_json.encode()).hexdigest()
attestation = client.create_attestation(
    subject={
        "type": "artifact",
        "id": signed.document_id,
        "digests": {"sha256": content_hash},
    },
    claims=[{"name": "reviewed_by", "value": "human", "confidence": 0.95}],
)
print(f"Attestation created: {attestation.document_id}")

# 4. Verify the attestation
result = client.verify_attestation(attestation.raw_json)
print(f"Valid: {result['valid']}")
print(f"Signature OK: {result['crypto']['signature_valid']}")
print(f"Hash OK: {result['crypto']['hash_valid']}")

# 5. Full verification (includes evidence checks)
full_result = client.verify_attestation(attestation.raw_json, full=True)
print(f"Full verify valid: {full_result['valid']}")
print(f"Evidence items: {len(full_result.get('evidence', []))}")
