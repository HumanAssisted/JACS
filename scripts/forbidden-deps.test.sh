#!/usr/bin/env bash
# Tests for scripts/forbidden-deps.sh.
#
# These are bash-script tests (not cargo tests) because the script itself
# is bash. Invoked by the rust-hygiene CI job alongside the actual guard
# call so any regression in the script is caught.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/forbidden-deps.sh"

if [[ ! -x "$SCRIPT" ]]; then
  echo "FAIL: $SCRIPT is not executable" >&2
  exit 1
fi

PASS=0
FAIL=0

assert_exit() {
  local expected="$1"; shift
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    local actual=0
  else
    local actual=$?
  fi
  if [[ "$actual" -eq "$expected" ]]; then
    echo "  PASS: $desc (exit $actual)"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $desc — expected exit $expected, got $actual" >&2
    FAIL=$((FAIL + 1))
  fi
}

cd "$HERE/.."

echo "Test 1: jacs-core (wasm32) must be clean"
assert_exit 0 "scripts/forbidden-deps.sh jacs-core wasm32-unknown-unknown" \
  bash "$SCRIPT" jacs-core wasm32-unknown-unknown

echo "Test 2: jacs (wasm32) must trip at least one forbidden crate"
assert_exit 1 "scripts/forbidden-deps.sh jacs wasm32-unknown-unknown" \
  bash "$SCRIPT" jacs wasm32-unknown-unknown

echo ""
echo "Summary: $PASS passed, $FAIL failed"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
