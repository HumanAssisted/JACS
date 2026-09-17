#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
cargo build -p jacs-mobile
case "$(uname -s)" in
    Darwin) library="target/debug/libjacs_mobile.dylib" ;;
    Linux) library="target/debug/libjacs_mobile.so" ;;
    *) echo "Set the host library path and invoke ubrn directly on Windows" >&2; exit 1 ;;
esac
# The generated TypeScript imports @ubjs/core@0.31.0-5 in the consuming package.
npx --yes --package uniffi-bindgen-react-native@0.31.0-5 ubrn \
    generate jsi bindings --library "$library" \
    --ts-dir jacs-mobile/generated/typescript \
    --cpp-dir jacs-mobile/generated/cpp --no-format
