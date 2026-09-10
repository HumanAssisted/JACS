#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# Inspect the final deployable pair without loading it. Runtime execution is a
# separate clean-environment smoke after the original source tree is moved away.
executable="${1:?consumer executable path is required}"
library="${2:?adjacent native library path is required}"
test -x "$executable"
test -f "$library"
executable_dir="$(cd "$(dirname "$executable")" && pwd -P)"
library_dir="$(cd "$(dirname "$library")" && pwd -P)"
if [[ "$executable_dir" != "$library_dir" ]]; then
  echo "consumer executable and native library must be adjacent" >&2
  exit 1
fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

reject() {
  echo "nonportable Go runtime linkage: $*" >&2
  exit 1
}

case "$(uname -s)" in
  Darwin)
    [[ "$(basename "$library")" == libjacsgo.dylib ]] || reject "unexpected library name"
    bash "$script_dir/check-macos-install-name.sh" "$library"
    for binary in "$executable" "$library"; do
      load_commands="$(otool -l "$binary")"
      if awk '$1 == "cmd" && $2 == "LC_RPATH" { found = 1 } END { exit found ? 0 : 1 }' <<< "$load_commands"; then
        reject "$binary must not have LC_RPATH; JACS uses its direct @loader_path identity"
      fi
      dependencies="$(otool -L "$binary" | sed '1d; s/^[[:space:]]*//; s/[[:space:]]*(compatibility version.*$//')"
      found_jacs=0
      while IFS= read -r dependency; do
        [[ -z "$dependency" ]] && continue
        case "$dependency" in
          '@loader_path/libjacsgo.dylib') found_jacs=1 ;;
          /usr/lib/*|/System/Library/*)
            [[ "/$dependency/" != *'/../'* && "/$dependency/" != *'/./'* ]] || reject "$dependency"
            ;;
          *) reject "$binary depends on $dependency" ;;
        esac
        case "$(basename "$dependency")" in
          libssl.*|libssl-*|libcrypto.*|libcrypto-*) reject "external OpenSSL: $dependency" ;;
        esac
      done <<< "$dependencies"
      [[ "$found_jacs" == 1 ]] || reject "$binary lacks the expected JACS library identity"
    done
    ;;
  Linux)
    [[ "$(basename "$library")" == libjacsgo.so ]] || reject "unexpected library name"
    for binary in "$executable" "$library"; do
      dynamic="$(readelf -d "$binary")"
      if [[ "$dynamic" == *'(RPATH)'* ]]; then
        reject "$binary has legacy DT_RPATH; only DT_RUNPATH is supported"
      fi
      if [[ "$dynamic" == *'(RUNPATH)'* || "$binary" == "$executable" ]]; then
        paths="$(sed -n -E '/\(RUNPATH\)/s/.*\[([^]]*)\].*/\1/p' <<< "$dynamic")"
        [[ "$paths" == '$ORIGIN' ]] || reject "$binary must have exactly DT_RUNPATH=\$ORIGIN"
      fi
      dependencies="$(sed -n -E '/\(NEEDED\)/s/.*\[([^]]+)\].*/\1/p' <<< "$dynamic")"
      found_jacs=0
      while IFS= read -r dependency; do
        [[ -z "$dependency" ]] && continue
        # Bare SONAMEs are resolved by the standard system loader during the
        # clean-environment run; do not build a second dependency resolver.
        [[ "$dependency" != */* ]] || reject "$binary depends on path $dependency"
        case "$dependency" in
          libssl.*|libssl-*|libcrypto.*|libcrypto-*) reject "external OpenSSL: $dependency" ;;
          libjacsgo.so) found_jacs=1 ;;
        esac
      done <<< "$dependencies"
      if [[ "$binary" == "$executable" && "$found_jacs" != 1 ]]; then
        reject "consumer lacks libjacsgo.so"
      fi
    done
    ;;
  *) reject "unsupported platform" ;;
esac
echo "JACSGO-RUNTIME-PATHS-OK $(basename "$executable")"
