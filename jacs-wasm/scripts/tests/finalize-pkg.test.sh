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
# a stub package.json (with auto-generated `name`) plus a placeholder
# `jacs_wasm.d.ts` so the staged tsc compile has *something* to chew on
# (we don't actually verify the TS output here — that's exercised by
# the real build in CI).
mkdir -p "${WORK_DIR}/pkg/worker"
cat > "${WORK_DIR}/pkg/package.json" <<JSON
{
  "name": "jacs-wasm",
  "version": "0.0.0-stub",
  "module": "jacs_wasm.js",
  "types": "jacs_wasm.d.ts"
}
JSON
cat > "${WORK_DIR}/pkg/jacs_wasm.d.ts" <<TS
// stub
export declare function initJacsWasm(): void;
TS
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
