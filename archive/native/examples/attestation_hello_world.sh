#!/bin/bash
# Attestation hello world -- create and verify your first attestation via CLI.
#
# Demonstrates the core attestation flow using the JACS CLI:
# sign a document, create an attestation, then verify it.
#
# Prerequisites:
#   cargo install jacs --features attestation
#   OR download the binary from releases
#
# Run:
#   bash examples/attestation_hello_world.sh
set -e

# Create a temporary workspace
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR"

echo "=== 1. Create a quickstart agent ==="
export JACS_PRIVATE_KEY_PASSWORD="HelloWorld!P@ss42"
jacs quickstart --algorithm ed25519

echo ""
echo "=== 2. Create a test document ==="
cat > mydata.json << 'ENDJSON'
{
  "action": "approve",
  "amount": 100,
  "reviewer": "human-operator"
}
ENDJSON

echo ""
echo "=== 3. Sign the document ==="
jacs document create -f mydata.json
echo "Document signed."

echo ""
echo "=== 4. Create an attestation ==="
DOC_HASH=$(sha256sum mydata.json | awk '{print $1}')
jacs attest create \
  --subject-type artifact \
  --subject-id "mydata-001" \
  --subject-digest "sha256:${DOC_HASH}" \
  --claims '[{"name": "reviewed_by", "value": "human", "confidence": 0.95}]'
echo "Attestation created."

echo ""
echo "=== 5. Verify the attestation ==="
# Find the most recent attestation file
ATT_FILE=$(ls -t jacs_data/documents/*.json 2>/dev/null | head -1)
if [ -n "$ATT_FILE" ]; then
  jacs attest verify "$ATT_FILE" --json
  echo "Verification complete."
else
  echo "No attestation file found -- check jacs_data/documents/"
fi

echo ""
echo "Done! Your first attestation has been created and verified."
