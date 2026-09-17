#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
cargo build -p jacs-mobile --features bindgen
case "$(uname -s)" in
    Darwin) library="target/debug/libjacs_mobile.dylib" ;;
    Linux) library="target/debug/libjacs_mobile.so" ;;
    *) echo "Use jacs-mobile-bindgen with your host DLL on this platform" >&2; exit 1 ;;
esac
for language in swift kotlin; do
    target/debug/jacs-mobile-bindgen generate --library "$library" \
        --language "$language" --config jacs-mobile/uniffi.toml \
        --out-dir "jacs-mobile/generated/$language" --no-format
done
