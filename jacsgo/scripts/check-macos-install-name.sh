#!/usr/bin/env bash
set -euo pipefail

# Read-only: consumers must test exactly the checksummed release bytes, never
# repair them or accidentally load a library left in the builder's directory.
library="${1:?native library path is required}"
test -f "$library"
if [[ "$(uname -s)" != Darwin ]]; then
  exit 0
fi
install_name="$(otool -D "$library" | sed -n '2p')"
if [[ "$install_name" != '@loader_path/libjacsgo.dylib' ]]; then
  echo "nonportable Go native library install name: $install_name" >&2
  exit 1
fi
codesign --verify --strict "$library"
