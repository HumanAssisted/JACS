#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}"
generated="${JACS_MOBILE_GENERATED_DIR:-$repo_root/jacs-mobile/generated}"
cargo build --locked -p jacs-mobile --features bindgen
case "$(uname -s)" in
    Darwin) library="$CARGO_TARGET_DIR/debug/libjacs_mobile.dylib" ;;
    Linux) library="$CARGO_TARGET_DIR/debug/libjacs_mobile.so" ;;
    *) echo "Use jacs-mobile-bindgen with your host DLL on this platform" >&2; exit 1 ;;
esac
for language in swift kotlin; do
    "$CARGO_TARGET_DIR/debug/jacs-mobile-bindgen" generate --library "$library" \
        --language "$language" --config jacs-mobile/uniffi.toml \
        --out-dir "$generated/$language" --no-format
done
