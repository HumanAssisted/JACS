#!/usr/bin/env bash
set -euo pipefail

failures=0
while IFS= read -r use; do
  ref=${use##*@}
  ref=${ref%% *}
  if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ERROR: mutable GitHub Action reference: $use" >&2
    failures=1
  fi
done < <(grep -RhoE 'uses:[[:space:]]*[^[:space:]]+@[^[:space:]]+' .github/workflows | sed -E 's/^uses:[[:space:]]*//')

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi

echo "OK: every GitHub Action reference is pinned to a full commit SHA"
