#!/usr/bin/env bash
# check-no-bare-serial.sh — Fail if any bare #[serial] (without a resource key)
# exists in jacs/src. This prevents reintroduction of crate-global serialization
# that degrades parallel test performance.
#
# Allowed:   #[serial(jacs_env)]  #[serial_test::serial(home_env)]
# Forbidden: #[serial]            #[serial_test::serial]
#
# Approved resource keys:
#   jacs_env             — JACS_* environment variables (process or jenv)
#   home_env             — HOME environment variable
#   cwd_env              — current working directory (set_current_dir)
#   keys_fetch_env       — JACS_KEYS_BASE_URL, HAI_KEYS_BASE_URL, JACS_KEY_FETCH_RETRIES
#   keychain_env         — OS keychain state (macOS Keychain / Linux Secret Service)
#   storage_conformance  — conformance test macro isolation
#
# Usage:
#   ./scripts/check-no-bare-serial.sh
#
# Exits 0 if no bare #[serial] found, 1 otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$REPO_ROOT/jacs/src"

found=0

# Match #[serial] as an annotation (not inside comments or strings).
# Grep for lines that have #[serial] at the end or followed by whitespace/newline,
# but NOT #[serial(...)].
if grep -rn '#\[serial\]' "$SRC_DIR/" 2>/dev/null | grep -v '^\s*//' | grep -v '^\s*\*' | grep -v '//.*#\[serial\]'; then
    found=1
fi

if grep -rn '#\[serial_test::serial\]' "$SRC_DIR/" 2>/dev/null | grep -v '^\s*//' | grep -v '^\s*\*' | grep -v '//.*#\[serial_test::serial\]'; then
    found=1
fi

if [ "$found" -eq 1 ]; then
    echo ""
    echo "ERROR: Bare #[serial] found in jacs/src/."
    echo "Use #[serial(key)] with one of the approved resource keys."
    echo "See scripts/check-no-bare-serial.sh for the list of approved keys."
    exit 1
fi

echo "OK: No bare #[serial] found in jacs/src/."
