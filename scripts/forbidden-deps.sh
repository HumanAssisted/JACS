#!/usr/bin/env bash
# Fail if a wasm-targeted crate (e.g. jacs-core, jacs-wasm) drags in a
# native-only dependency. Single source of truth for the forbidden list —
# do not duplicate it in docs.
#
# Usage:
#   scripts/forbidden-deps.sh <crate> [<target>]
#
# Examples:
#   scripts/forbidden-deps.sh jacs-core wasm32-unknown-unknown
#   scripts/forbidden-deps.sh jacs-wasm wasm32-unknown-unknown
#
# Exit codes:
#   0 — no forbidden dep present
#   1 — at least one forbidden dep found (names printed)
#   2 — invocation error
#
# See PRD §4.7 (JACS WASM PRD).

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <crate> [<target>]" >&2
  exit 2
fi

CRATE="$1"
TARGET="${2:-}"

# Native crates that must never appear in the jacs-core / jacs-wasm dependency
# tree. Each one was verified by WASM_FINDINGS to either fail to compile on
# wasm32-unknown-unknown or to bloat the bundle unnecessarily.
FORBIDDEN=(
  ring
  tokio
  reqwest
  hickory-resolver
  object_store
  rusqlite
  sqlx
  duckdb
  surrealdb
  keyring
  rpassword
  dirs
  jacs-media
  mail-parser
  html5ever
  opentelemetry-otlp
)

CARGO_ARGS=(tree -p "$CRATE" --prefix none --no-dedupe)
if [[ -n "$TARGET" ]]; then
  CARGO_ARGS+=(--target "$TARGET")
fi

# Capture the tree once. cargo-tree prints to stdout.
if ! TREE_OUTPUT="$(cargo "${CARGO_ARGS[@]}" 2>&1)"; then
  echo "ERROR: cargo tree failed for crate '$CRATE'${TARGET:+ (target $TARGET)}:" >&2
  echo "$TREE_OUTPUT" >&2
  exit 2
fi

FOUND=()
for dep in "${FORBIDDEN[@]}"; do
  # Match either bare crate name at line start ("ring v0.17.9") or after a
  # path separator. Use grep -E with word boundaries to avoid prefix matches
  # like "ring" matching "tracing-ring".
  if grep -Eq "(^|[[:space:]])${dep}[[:space:]]+v" <<<"$TREE_OUTPUT"; then
    FOUND+=("$dep")
  fi
done

if [[ ${#FOUND[@]} -gt 0 ]]; then
  echo "ERROR: forbidden dep(s) found in '$CRATE'${TARGET:+ (target $TARGET)}:" >&2
  for dep in "${FOUND[@]}"; do
    echo "  - $dep" >&2
  done
  echo "" >&2
  echo "These crates are native-only and must not be reachable from $CRATE." >&2
  echo "See PRD §4.7 (JACS_WASM_PRD.md) for the full list rationale." >&2
  exit 1
fi

echo "OK: '$CRATE'${TARGET:+ (target $TARGET)} has no forbidden deps."
exit 0
