#!/usr/bin/env bash
# Finalize the wasm-pack-produced `jacs-wasm/pkg/` directory into a
# publishable `@jacs/wasm` npm package (Task 020).
#
# 1. Reads the version from `jacs-wasm/Cargo.toml` so the npm version
#    matches the Rust crate version (PRD §4.8 + version-bump checklist).
# 2. Merges `jacs-wasm/package.template.json` into `pkg/package.json`
#    via Python json (avoids a `jq` dependency on dev machines).
# 3. Compiles the hand-written `index.ts` + `worker/*.ts` to JS + d.ts
#    via the workspace tsconfig and copies them into `pkg/`.
# 4. Copies `jacs-wasm/README.md` into `pkg/` so npm shows the README.
#
# Idempotent — safe to re-run.

set -euo pipefail

JACS_WASM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="${JACS_WASM_DIR}/pkg"
TEMPLATE="${JACS_WASM_DIR}/package.template.json"

if [[ ! -d "${PKG_DIR}" ]]; then
    echo "error: ${PKG_DIR} does not exist. Run 'wasm-pack build --target web --release jacs-wasm' first." >&2
    exit 1
fi

if [[ ! -f "${TEMPLATE}" ]]; then
    echo "error: ${TEMPLATE} missing. The template ships in the repo; this script cannot run without it." >&2
    exit 1
fi

# --- 1. Extract version from Cargo.toml ---
CARGO_VERSION="$(grep -E '^version[[:space:]]*=' "${JACS_WASM_DIR}/Cargo.toml" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
if [[ -z "${CARGO_VERSION}" ]]; then
    echo "error: could not extract version from ${JACS_WASM_DIR}/Cargo.toml" >&2
    exit 1
fi
echo "finalize-pkg: version = ${CARGO_VERSION}"

# --- 2. Merge template into pkg/package.json ---
python3 - "${PKG_DIR}/package.json" "${TEMPLATE}" "${CARGO_VERSION}" <<'PY'
import json
import sys

pkg_path, template_path, version = sys.argv[1], sys.argv[2], sys.argv[3]
with open(pkg_path, "r", encoding="utf-8") as fh:
    pkg = json.load(fh)
with open(template_path, "r", encoding="utf-8") as fh:
    template = json.load(fh)

# Template takes precedence on every field it specifies.
pkg.update(template)
pkg["version"] = version

with open(pkg_path, "w", encoding="utf-8") as fh:
    json.dump(pkg, fh, indent=2, sort_keys=False)
    fh.write("\n")
print(f"finalize-pkg: wrote {pkg_path} (version={version})")
PY

# --- 3. Build the hand-written TS wrapper ---
# The hand-written `index.ts` and `worker/*.ts` reference
# `./jacs_wasm.js` / `../jacs_wasm.js` because that's the layout
# *inside* the published pkg/ directory. We stage them into pkg/
# before running tsc so the import paths resolve correctly against
# the wasm-bindgen output that already lives in pkg/. The staged
# .ts sources are removed after compile so only the compiled .js +
# .d.ts ship in the npm package.
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGE_DIR}"' EXIT

# Stage the .ts sources alongside the wasm-bindgen .d.ts into a temp
# directory; compile in-place; copy the resulting .js/.d.ts back into
# pkg/. Compiling outside pkg/ avoids the tsc rule that auto-excludes
# `outDir` from the include set when they overlap.
mkdir -p "${STAGE_DIR}/worker"
cp "${JACS_WASM_DIR}/index.ts" "${STAGE_DIR}/index.ts"
cp "${JACS_WASM_DIR}/worker/index.ts" "${STAGE_DIR}/worker/index.ts"
cp "${JACS_WASM_DIR}/worker/jacs-worker.ts" "${STAGE_DIR}/worker/jacs-worker.ts"
# Pull in the wasm-bindgen-generated declaration so the staged
# `index.ts` / `worker/jacs-worker.ts` can resolve `./jacs_wasm.js`.
cp "${PKG_DIR}/jacs_wasm.d.ts" "${STAGE_DIR}/jacs_wasm.d.ts"

cat > "${STAGE_DIR}/tsconfig.json" <<JSON
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ES2020",
    "moduleResolution": "bundler",
    "lib": ["ES2020", "DOM", "DOM.Iterable", "WebWorker"],
    "strict": true,
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "skipLibCheck": true,
    "isolatedModules": true,
    "declaration": true,
    "noEmitOnError": false,
    "outDir": "./out",
    "rootDir": "."
  },
  "include": [
    "./index.ts",
    "./worker/*.ts",
    "./jacs_wasm.d.ts"
  ]
}
JSON

if command -v tsc >/dev/null 2>&1; then
    echo "finalize-pkg: tsc -p ${STAGE_DIR}/tsconfig.json"
    (cd "${STAGE_DIR}" && tsc -p tsconfig.json) \
        || echo "warning: tsc reported diagnostics (output files may still be present)"
elif command -v npx >/dev/null 2>&1; then
    echo "finalize-pkg: npx tsc -p ${STAGE_DIR}/tsconfig.json"
    (cd "${STAGE_DIR}" && npx --yes -p typescript@5 tsc -p tsconfig.json) \
        || echo "warning: tsc reported diagnostics"
else
    echo "warning: tsc not available; skipping TypeScript wrapper compile." >&2
    echo "         install Node + typescript to produce index.js + worker/index.js" >&2
fi

# Copy the compiled outputs back into pkg/. Skip the staged copy of
# `jacs_wasm.d.ts` (which would clobber the real one).
mkdir -p "${PKG_DIR}/worker"
if [[ -d "${STAGE_DIR}/out" ]]; then
    cp "${STAGE_DIR}/out/index.js" "${PKG_DIR}/index.js" 2>/dev/null || true
    cp "${STAGE_DIR}/out/index.d.ts" "${PKG_DIR}/index.d.ts" 2>/dev/null || true
    cp "${STAGE_DIR}/out/worker/index.js" "${PKG_DIR}/worker/index.js" 2>/dev/null || true
    cp "${STAGE_DIR}/out/worker/index.d.ts" "${PKG_DIR}/worker/index.d.ts" 2>/dev/null || true
    cp "${STAGE_DIR}/out/worker/jacs-worker.js" "${PKG_DIR}/worker/jacs-worker.js" 2>/dev/null || true
    cp "${STAGE_DIR}/out/worker/jacs-worker.d.ts" "${PKG_DIR}/worker/jacs-worker.d.ts" 2>/dev/null || true
fi

# --- 4. Copy README so npm shows it on the package page ---
if [[ -f "${JACS_WASM_DIR}/README.md" ]]; then
    cp "${JACS_WASM_DIR}/README.md" "${PKG_DIR}/README.md"
    echo "finalize-pkg: copied README.md"
fi

echo "finalize-pkg: done. Inspect ${PKG_DIR}/package.json + run 'npm pack --dry-run --workspaces=false' from ${PKG_DIR}."
