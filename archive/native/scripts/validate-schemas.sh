#!/usr/bin/env bash
# validate-schemas.sh — Verify all JACS schema files have correct $id fields
# and are valid JSON. Exits non-zero if any check fails.
#
# Usage:
#   ./scripts/validate-schemas.sh [SCHEMA_DIR]
#
# SCHEMA_DIR defaults to jacs/schemas relative to the repo root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCHEMA_DIR="${1:-$REPO_ROOT/jacs/schemas}"

if [ ! -d "$SCHEMA_DIR" ]; then
  echo "ERROR: Schema directory not found: $SCHEMA_DIR"
  exit 1
fi

ERRORS=0
CHECKED=0

while IFS= read -r -d '' schema_file; do
  CHECKED=$((CHECKED + 1))
  rel_path="${schema_file#"$SCHEMA_DIR/"}"

  # Check 1: Valid JSON
  if ! python3 -c "import json; json.load(open('$schema_file'))" 2>/dev/null; then
    echo "FAIL: Invalid JSON: $rel_path"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  # Check 2: Has $id field
  id_value=$(python3 -c "import json; d=json.load(open('$schema_file')); print(d.get('\$id', ''))" 2>/dev/null)
  if [ -z "$id_value" ]; then
    echo "FAIL: Missing \$id field: $rel_path"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  # Check 3: $id starts with https://hai.ai/schemas/
  if [[ "$id_value" != https://hai.ai/schemas/* ]]; then
    echo "FAIL: \$id does not start with https://hai.ai/schemas/: $rel_path"
    echo "  got: $id_value"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  # Check 4: $id path matches file path
  expected_id="https://hai.ai/schemas/$rel_path"
  if [ "$id_value" != "$expected_id" ]; then
    echo "FAIL: \$id does not match file path: $rel_path"
    echo "  expected: $expected_id"
    echo "  got:      $id_value"
    ERRORS=$((ERRORS + 1))
    continue
  fi

  echo "  OK: $rel_path"
done < <(find "$SCHEMA_DIR" -name "*.schema.json" -print0 | sort -z)

echo ""
echo "Checked $CHECKED schemas, $ERRORS errors."

if [ "$ERRORS" -gt 0 ]; then
  exit 1
fi

echo "All schema validations passed."
