#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/seal-changelog.sh seal    [VERSION]   # flip (unreleased) -> Released YYYY-MM-DD
#   ./scripts/seal-changelog.sh check   [VERSION]   # fail if block still says (unreleased)
#
# VERSION defaults to the version in jacs/Cargo.toml.
# Idempotent: re-running seal on an already-sealed block is a no-op.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

MODE="${1:-}"
if [[ "$MODE" != "seal" && "$MODE" != "check" ]]; then
  echo "Usage: $0 [seal|check] [VERSION]" >&2
  exit 2
fi

VERSION="${2:-$(grep '^version' jacs/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')}"
CHANGELOG="CHANGELOG.md"

if [[ ! -f "$CHANGELOG" ]]; then
  echo "ERROR: $CHANGELOG not found" >&2
  exit 1
fi

# Confirm the version block exists.
if ! grep -q "^## ${VERSION}\$" "$CHANGELOG"; then
  echo "ERROR: $CHANGELOG has no '## ${VERSION}' section" >&2
  exit 1
fi

TODAY="$(date +%Y-%m-%d)"

case "$MODE" in
  seal)
    # Within the ## VERSION block (until the next ## heading), replace a lone
    # "(unreleased)" line with "Released YYYY-MM-DD". Other content untouched.
    set +e
    awk -v ver="$VERSION" -v date="$TODAY" '
      BEGIN { in_block = 0; sealed = 0 }
      /^## / {
        if (in_block) in_block = 0
        if ($0 == "## " ver) in_block = 1
        print
        next
      }
      in_block && $0 == "(unreleased)" {
        print "Released " date
        sealed = 1
        next
      }
      { print }
      END { exit (sealed ? 0 : 2) }
    ' "$CHANGELOG" > "$CHANGELOG.tmp"
    AWK_STATUS=$?
    set -e

    if [[ $AWK_STATUS -eq 0 ]]; then
      mv "$CHANGELOG.tmp" "$CHANGELOG"
      echo "  sealed ## ${VERSION} -> Released ${TODAY}"
    elif [[ $AWK_STATUS -eq 2 ]]; then
      rm -f "$CHANGELOG.tmp"
      echo "  ## ${VERSION} already sealed (no '(unreleased)' line) — leaving as-is"
    else
      rm -f "$CHANGELOG.tmp"
      echo "ERROR: awk failed with status $AWK_STATUS" >&2
      exit 1
    fi
    ;;
  check)
    # Strict gate: must NOT contain a (unreleased) line in the version block.
    if awk -v ver="$VERSION" '
      /^## / { in_block = ($0 == "## " ver) }
      in_block && $0 == "(unreleased)" { exit 1 }
    ' "$CHANGELOG"; then
      echo "  ✓ CHANGELOG.md ## ${VERSION} is sealed"
    else
      echo "ERROR: CHANGELOG.md ## ${VERSION} still says '(unreleased)'." >&2
      echo "  Run 'make seal-changelog' (and commit) before releasing." >&2
      exit 1
    fi
    ;;
esac
