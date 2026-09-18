#!/usr/bin/env bash
set -euo pipefail
# Usage: ./scripts/bump-version.sh [major|minor|patch]
# Validates the focused release and archived active-core edges, without network access.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$REPO_ROOT/scripts/bump_version.py" "$@"
