#!/usr/bin/env bash
# Test fixture for Issue 009 — verify that `npm install` of the finalized
# `@jacs/wasm` tarball resolves to the hand-written wrapper via top-level
# `main` / `module` / `types` *without* a Vite alias. Catches regressions
# where the legacy fields would otherwise point at the raw wasm-bindgen
# output.
#
# Run: `bash jacs-wasm/scripts/tests/package-consumption.test.sh`.
# Exit 0 = pass. The script is also wired into wasm-pr.yml and
# release-wasm.yml.
#
# Requires: node + npm in $PATH, and a finalized `jacs-wasm/pkg/`
# directory (`wasm-pack build --target web --release jacs-wasm` +
# `jacs-wasm/scripts/finalize-pkg.sh`). The script will fail loudly if
# the prerequisites are missing.

set -euo pipefail

JACS_WASM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_DIR="${JACS_WASM_DIR}/pkg"

if [[ ! -f "${PKG_DIR}/package.json" ]]; then
    echo "error: ${PKG_DIR}/package.json missing. Run wasm-pack build + finalize-pkg.sh first." >&2
    exit 1
fi
if [[ ! -f "${PKG_DIR}/index.js" || ! -f "${PKG_DIR}/index.d.ts" ]]; then
    # Without the finalized hand-written wrapper outputs we cannot prove
    # the package metadata resolves to them. Surface this loudly so the
    # bisect target is obvious.
    echo "error: ${PKG_DIR}/index.js or index.d.ts missing — run finalize-pkg.sh first." >&2
    exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

# 1. Pack the candidate package without publishing.
PACK_DIR="${WORK_DIR}/pack"
mkdir -p "${PACK_DIR}"
( cd "${PKG_DIR}" && npm pack --silent --pack-destination "${PACK_DIR}" >/dev/null )
TARBALL="$(ls "${PACK_DIR}"/*.tgz | head -1)"
if [[ -z "${TARBALL}" ]]; then
    echo "error: npm pack did not produce a tarball under ${PACK_DIR}" >&2
    exit 1
fi
echo "package-consumption.test: packed ${TARBALL}"

# 2. Build a fresh sandbox and install the tarball without aliases.
CONSUMER_DIR="${WORK_DIR}/consumer"
mkdir -p "${CONSUMER_DIR}"
cat > "${CONSUMER_DIR}/package.json" <<JSON
{
  "name": "jacs-wasm-consumption-fixture",
  "private": true,
  "version": "0.0.0",
  "type": "module"
}
JSON
( cd "${CONSUMER_DIR}" && npm install --silent --no-audit --no-fund "${TARBALL}" >/dev/null )

# 3. Resolve `@jacs/wasm`'s package.json from the sandbox and assert the
# top-level legacy fields point at the wrapper (Issue 009 contract). We
# write the verification script into the sandbox and run it there so
# Node resolves `@jacs/wasm` from the freshly installed tarball without
# the wrapper repo's `node_modules` shadowing it.
cat > "${CONSUMER_DIR}/verify.mjs" <<'NODE'
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Read package.json directly from the installed tarball location — the
// package itself doesn't have to expose './package.json' via the
// `exports` map for this verification to work.
const pkgPath = path.join(__dirname, "node_modules", "@jacs", "wasm", "package.json");
const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));

const errors = [];
function expect(cond, msg) {
  if (!cond) errors.push(msg);
}

expect(pkg.name === "@jacs/wasm",
  `name=${pkg.name}, expected '@jacs/wasm'`);
expect(pkg.main === "index.js",
  `main=${pkg.main}, expected 'index.js' (Issue 009)`);
expect(pkg.module === "index.js",
  `module=${pkg.module}, expected 'index.js' (Issue 009)`);
expect(pkg.types === "index.d.ts",
  `types=${pkg.types}, expected 'index.d.ts' (Issue 009)`);
expect(pkg.type === "module",
  `type=${pkg.type}, expected 'module'`);
expect(pkg.exports && pkg.exports["."] && pkg.exports["."].import === "./index.js",
  `exports['.'].import wrong: ${JSON.stringify(pkg.exports?.["."])}`);
expect(pkg.exports && pkg.exports["./worker"] && pkg.exports["./worker"].import === "./worker/index.js",
  `exports['./worker'].import wrong: ${JSON.stringify(pkg.exports?.["./worker"])}`);
// Raw wasm-bindgen escape hatch under `./pkg/*` so callers who need the
// unwrapped module can still opt in by subpath.
expect(pkg.exports && pkg.exports["./pkg/*"],
  `exports['./pkg/*'] missing (raw wasm-bindgen escape hatch)`);

// Resolve the root specifier — must land at the wrapper, not the raw
// wasm-bindgen module. `import.meta.resolve` honours the `exports` map,
// which is the resolution path real ESM consumers exercise.
const rootEntry = import.meta.resolve("@jacs/wasm");
const rootUrl = new URL(rootEntry);
const rootBase = path.basename(rootUrl.pathname);
expect(rootBase === "index.js",
  `resolve('@jacs/wasm') → '${rootBase}', expected 'index.js'`);
// Worker subpath should also be exposed.
const workerEntry = import.meta.resolve("@jacs/wasm/worker");
const workerBase = path.basename(new URL(workerEntry).pathname);
expect(workerBase === "index.js",
  `resolve('@jacs/wasm/worker') → '${workerBase}', expected 'index.js'`);

if (errors.length) {
  console.error("PACKAGE-CONSUMPTION TEST FAILED:");
  for (const e of errors) console.error("  - " + e);
  console.error(`\nResolved package.json: ${pkgPath}`);
  process.exit(1);
}

console.log("package-consumption.test: OK — npm package metadata routes @jacs/wasm to the hand-written wrapper");
NODE

( cd "${CONSUMER_DIR}" && node verify.mjs )

echo "package-consumption.test: PASS"
