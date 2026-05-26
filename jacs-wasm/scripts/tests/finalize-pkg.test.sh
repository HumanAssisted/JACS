#!/usr/bin/env bash
# Test fixture for `scripts/finalize-pkg.sh` (Task 020). Verifies:
#
# 1. The script reads the version from `jacs-wasm/Cargo.toml`.
# 2. The merged `pkg/package.json` carries `name: "@jacs/wasm"`, the
#    right `version`, the `exports` map (including `./worker`), and
#    `files` listing the expected artifacts.
#
# Run: `bash jacs-wasm/scripts/tests/finalize-pkg.test.sh`. Exit 0 = pass.

set -euo pipefail

JACS_WASM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

# Set up a minimal fake pkg/ that mirrors what wasm-pack would emit:
# a stub package.json (with auto-generated `name`) plus a `jacs_wasm.d.ts`
# that mirrors the full wasm-bindgen public surface so the staged tsc
# compile can resolve every symbol the hand-written `index.ts` /
# `worker/jacs-worker.ts` imports. We re-use the checked-in source-tree
# stub `jacs-wasm/jacs_wasm.d.ts` (already maintained by Task 032 for the
# `tsc --noEmit -p tsconfig.json` smoke) so this fixture cannot drift
# behind the wrapper imports again (Issue 008).
mkdir -p "${WORK_DIR}/pkg/worker"
cat > "${WORK_DIR}/pkg/package.json" <<JSON
{
  "name": "jacs-wasm",
  "version": "0.0.0-stub",
  "module": "jacs_wasm.js",
  "types": "jacs_wasm.d.ts"
}
JSON
# Copy the maintained, full-surface stub instead of writing an inline
# placeholder — keeps the fixture and the source-tree `tsc --noEmit` in
# lockstep on every wasm-bindgen surface change.
cp "${JACS_WASM_DIR}/jacs_wasm.d.ts" "${WORK_DIR}/pkg/jacs_wasm.d.ts"
touch "${WORK_DIR}/pkg/jacs_wasm.js" "${WORK_DIR}/pkg/jacs_wasm_bg.wasm" "${WORK_DIR}/pkg/jacs_wasm_bg.wasm.d.ts"

# Symlink the test pkg/ into the real JACS_WASM_DIR location so
# finalize-pkg.sh finds it. We can't safely modify the real pkg/, so
# we run the script in a sandboxed copy of jacs-wasm/.
SANDBOX="${WORK_DIR}/jacs-wasm"
mkdir -p "${SANDBOX}/scripts"
cp "${JACS_WASM_DIR}/Cargo.toml" "${SANDBOX}/Cargo.toml"
cp "${JACS_WASM_DIR}/package.template.json" "${SANDBOX}/package.template.json"
cp "${JACS_WASM_DIR}/index.ts" "${SANDBOX}/index.ts"
cp -r "${JACS_WASM_DIR}/worker" "${SANDBOX}/worker"
[[ -f "${JACS_WASM_DIR}/README.md" ]] && cp "${JACS_WASM_DIR}/README.md" "${SANDBOX}/README.md" || true
cp "${JACS_WASM_DIR}/scripts/finalize-pkg.sh" "${SANDBOX}/scripts/finalize-pkg.sh"
cp -r "${WORK_DIR}/pkg" "${SANDBOX}/pkg"

bash "${SANDBOX}/scripts/finalize-pkg.sh" >"${WORK_DIR}/finalize.log" 2>&1 \
    || { echo "FAIL: finalize-pkg.sh exited non-zero"; cat "${WORK_DIR}/finalize.log"; exit 1; }

# --- Assertions ---

PKG_JSON="${SANDBOX}/pkg/package.json"

python3 - "${PKG_JSON}" "${SANDBOX}/Cargo.toml" <<'PY'
import json
import re
import sys

pkg_path, cargo_path = sys.argv[1], sys.argv[2]
with open(pkg_path) as fh:
    pkg = json.load(fh)
with open(cargo_path) as fh:
    cargo_txt = fh.read()

cargo_version = re.search(r'^version\s*=\s*"([^"]+)"', cargo_txt, re.M).group(1)

errors = []
def expect(cond, msg):
    if not cond:
        errors.append(msg)

expect(pkg.get("name") == "@jacs/wasm", f"name={pkg.get('name')!r}, expected @jacs/wasm")
expect(pkg.get("version") == cargo_version, f"version={pkg.get('version')!r}, expected {cargo_version!r}")
expect(pkg.get("type") == "module", f"type={pkg.get('type')!r}, expected module")
expect(pkg.get("sideEffects") is False, f"sideEffects={pkg.get('sideEffects')!r}, expected false")

# Issue 009 — top-level main/module/types must point at the hand-written
# wrapper (index.js / index.d.ts), not the raw wasm-bindgen output
# (jacs_wasm.js / jacs_wasm.d.ts). Consumers and tools that read the
# legacy fields instead of the `exports` map otherwise bypass the
# PRD §4.3 surface (initJacsWasm, async constructors, localStore, etc.).
expect(pkg.get("main") == "index.js",
       f"main={pkg.get('main')!r}, expected 'index.js' (Issue 009)")
expect(pkg.get("module") == "index.js",
       f"module={pkg.get('module')!r}, expected 'index.js' (Issue 009)")
expect(pkg.get("types") == "index.d.ts",
       f"types={pkg.get('types')!r}, expected 'index.d.ts' (Issue 009)")

files = pkg.get("files", [])
for required in ["jacs_wasm.js", "jacs_wasm.d.ts", "jacs_wasm_bg.wasm",
                 "index.js", "index.d.ts",
                 "worker/index.js", "worker/index.d.ts"]:
    expect(required in files, f"files missing {required!r}; got {files}")

exports = pkg.get("exports", {})
expect("." in exports, f"exports missing root '.'; got {sorted(exports)}")
expect("./worker" in exports, f"exports missing './worker'; got {sorted(exports)}")
expect(exports.get(".", {}).get("import") == "./index.js", f"./ import wrong: {exports.get('.')}")
expect(exports.get("./worker", {}).get("import") == "./worker/index.js",
       f"./worker import wrong: {exports.get('./worker')}")
# Raw wasm-bindgen escape hatch under `./pkg/*` (Issue 009 — deliberate
# subpath so a consumer who needs the unwrapped surface can opt in).
expect("./pkg/*" in exports,
       f"exports missing './pkg/*' raw-wasm-bindgen escape hatch; got {sorted(exports)}")

keywords = pkg.get("keywords", [])
for required in ["jacs", "wasm", "signing", "agents"]:
    expect(required in keywords, f"keywords missing {required!r}; got {keywords}")

if errors:
    print("ASSERTIONS FAILED:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
print("OK: pkg/package.json matches template + Cargo version")
PY

echo "finalize-pkg.test: PASS"
