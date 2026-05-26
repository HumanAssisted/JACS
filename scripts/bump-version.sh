#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/bump-version.sh [major|minor|patch]
# Bumps the JACS version across all files listed in RELEASING.md.
# Storage backend crates always get a patch bump + jacs dep update.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

BUMP_TYPE="${1:-}"
if [[ ! "$BUMP_TYPE" =~ ^(major|minor|patch)$ ]]; then
  echo "Usage: $0 [major|minor|patch]"
  echo ""
  echo "  major  — X.0.0  (breaking changes)"
  echo "  minor  — 0.X.0  (new features)"
  echo "  patch  — 0.0.X  (bug fixes)"
  exit 1
fi

# --- Read current versions ---

CURRENT=$(grep '^version' jacs/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

case "$BUMP_TYPE" in
  major) NEW_VERSION="$((MAJOR + 1)).0.0" ;;
  minor) NEW_VERSION="${MAJOR}.$((MINOR + 1)).0" ;;
  patch) NEW_VERSION="${MAJOR}.${MINOR}.$((PATCH + 1))" ;;
esac

echo "Main version: $CURRENT -> $NEW_VERSION"

# --- Helper: bump a semver string by patch ---
bump_patch() {
  local ver="$1"
  local ma mi pa
  IFS='.' read -r ma mi pa <<< "$ver"
  echo "${ma}.${mi}.$((pa + 1))"
}

# --- Main crate package versions ---

MAIN_CARGO_FILES=(
  jacs/Cargo.toml
  jacs-core/Cargo.toml
  jacs-wasm/Cargo.toml
  binding-core/Cargo.toml
  jacs-cli/Cargo.toml
  jacs-mcp/Cargo.toml
  jacs-media/Cargo.toml
  jacsnpm/Cargo.toml
  jacspy/Cargo.toml
  jacsgo/lib/Cargo.toml
)

for f in "${MAIN_CARGO_FILES[@]}"; do
  # Replace only the first version = "..." line (package version)
  sed -i '' "s/^version = \"$CURRENT\"/version = \"$NEW_VERSION\"/" "$f"
  echo "  $f: package version"
done

# --- Inter-crate dependency versions ---
# These appear as: version = "X.Y.Z" (inside dependency declarations, not at line start)
# We use replace-all since the old version is unique enough.

DEP_FILES=(
  jacs/Cargo.toml
  jacs-wasm/Cargo.toml
  binding-core/Cargo.toml
  jacs-cli/Cargo.toml
  jacs-mcp/Cargo.toml
)

for f in "${DEP_FILES[@]}"; do
  sed -i '' "s/version = \"$CURRENT\"/version = \"$NEW_VERSION\"/g" "$f"
  echo "  $f: dependency versions"
done

# --- Non-Rust manifests ---

sed -i '' "s/\"version\": \"$CURRENT\"/\"version\": \"$NEW_VERSION\"/" jacsnpm/package.json
echo "  jacsnpm/package.json"

sed -i '' "s/^version = \"$CURRENT\"/version = \"$NEW_VERSION\"/" jacspy/pyproject.toml
echo "  jacspy/pyproject.toml"

# @jacs/wasm npm package — version lives in the finalize-pkg template
# (Task 020). Only touch it when the file is present so a half-finished
# tree (e.g. mid-port) does not error out.
if [ -f jacs-wasm/package.template.json ]; then
  sed -i '' "s/\"version\": \"$CURRENT\"/\"version\": \"$NEW_VERSION\"/" jacs-wasm/package.template.json
  echo "  jacs-wasm/package.template.json"
fi

# --- Contract / metadata ---

sed -i '' "s/\"version\": \"$CURRENT\"/\"version\": \"$NEW_VERSION\"/" jacs-mcp/contract/jacs-mcp-contract.json
echo "  jacs-mcp/contract/jacs-mcp-contract.json"

# --- Documentation footers ---
# Use regex anchors matching the footer format (not $CURRENT) so a drifted
# README still gets fixed on the next bump.

# README.md footer: "v0.9.7 | [Apache-2.0](./LICENSE-APACHE) | ..."
sed -i '' -E "s#^v[0-9]+\.[0-9]+\.[0-9]+ \| \[Apache-2\.0\]#v${NEW_VERSION} | [Apache-2.0]#" README.md
echo "  README.md"

# jacs/README.md footer: "**Version**: 0.9.7 | [HAI.AI](https://hai.ai)"
sed -i '' -E "s#^\*\*Version\*\*: [0-9]+\.[0-9]+\.[0-9]+#**Version**: ${NEW_VERSION}#" jacs/README.md
echo "  jacs/README.md"

# jacs-cli/README.md footer: "v0.9.7 | [Apache-2.0](../LICENSE-APACHE)"
sed -i '' -E "s#^v[0-9]+\.[0-9]+\.[0-9]+ \| \[Apache-2\.0\]#v${NEW_VERSION} | [Apache-2.0]#" jacs-cli/README.md
echo "  jacs-cli/README.md"

# Fail loudly if any README footer did not update to $NEW_VERSION.
README_DRIFT=0
if ! grep -q "^v${NEW_VERSION} | \[Apache-2\.0\]" README.md; then
  echo "  ERROR: README.md footer did not update to v${NEW_VERSION}"
  README_DRIFT=1
fi
if ! grep -q "^\*\*Version\*\*: ${NEW_VERSION} " jacs/README.md; then
  echo "  ERROR: jacs/README.md footer did not update to ${NEW_VERSION}"
  README_DRIFT=1
fi
if ! grep -q "^v${NEW_VERSION} | \[Apache-2\.0\]" jacs-cli/README.md; then
  echo "  ERROR: jacs-cli/README.md footer did not update to v${NEW_VERSION}"
  README_DRIFT=1
fi
if [ "$README_DRIFT" -ne 0 ]; then
  exit 1
fi

# --- CHANGELOG: add new section ---

CHANGELOG_HEADER="## $NEW_VERSION"
if ! grep -q "^## $NEW_VERSION" CHANGELOG.md; then
  sed -i '' "1s/^/$CHANGELOG_HEADER\n\n(unreleased)\n\n/" CHANGELOG.md
  echo "  CHANGELOG.md: added $CHANGELOG_HEADER section"
else
  echo "  CHANGELOG.md: $CHANGELOG_HEADER already exists, skipping"
fi

# --- Storage backend crates ---
# Always patch-bump + update jacs dep.

STORAGE_CRATES=(jacs-duckdb jacs-redb jacs-surrealdb jacs-postgresql)

echo ""
echo "Storage backend crates:"

for crate in "${STORAGE_CRATES[@]}"; do
  f="$crate/Cargo.toml"
  STORAGE_CURRENT=$(grep '^version' "$f" | head -1 | sed 's/.*"\(.*\)"/\1/')
  STORAGE_NEW=$(bump_patch "$STORAGE_CURRENT")

  # Bump package version
  sed -i '' "s/^version = \"$STORAGE_CURRENT\"/version = \"$STORAGE_NEW\"/" "$f"

  # Update jacs dependency version
  sed -i '' "s/jacs = { version = \"$CURRENT\"/jacs = { version = \"$NEW_VERSION\"/" "$f"

  echo "  $f: $STORAGE_CURRENT -> $STORAGE_NEW (jacs dep -> $NEW_VERSION)"
done

# --- Regenerate lockfile ---

echo ""
echo "Regenerating Cargo.lock..."
cargo generate-lockfile 2>/dev/null

# --- Verify ---

echo ""
echo "Verifying..."
make check-versions

echo ""
echo "Done! All versions bumped to $NEW_VERSION."
echo ""
echo "Next steps:"
echo "  1. Update CHANGELOG.md with release notes"
echo "  2. git add -A && git commit -m 'Bump version to $NEW_VERSION'"
echo "  3. git push"
echo "  4. make release-everything"
