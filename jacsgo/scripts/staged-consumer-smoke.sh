#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
bundle="${2:-}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
  echo "usage: $0 X.Y.Z /path/to/release-bundle" >&2
  exit 2
fi
if [[ -z "$bundle" || ! -d "$bundle" ]]; then
  echo "release bundle directory is required" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/../.." && pwd -P)"
bundle="$(cd "$bundle" && pwd -P)"
goos="$(go env GOOS)"
goarch="$(go env GOARCH)"

case "$goos/$goarch" in
  darwin/amd64|darwin/arm64)
    extension="dylib"
    library_name="libjacsgo.dylib"
    ;;
  linux/amd64|linux/arm64)
    extension="so"
    library_name="libjacsgo.so"
    ;;
  *)
    echo "unsupported staged jacsgo target: $goos/$goarch" >&2
    exit 2
    ;;
esac

asset_name="jacsgo-v${version}-${goos}-${goarch}.${extension}"
asset="$bundle/artifacts/$asset_name"
manifest="$bundle/jacsgo-v${version}-sha256sums.txt"
test -f "$asset" || { echo "missing staged asset: $asset" >&2; exit 1; }
test -f "$manifest" || { echo "missing staged checksum manifest: $manifest" >&2; exit 1; }

mapfile_compat="$(awk -v asset="$asset_name" '$2 == asset { print $1 }' "$manifest")"
if [[ ! "$mapfile_compat" =~ ^[0-9a-f]{64}$ ]]; then
  echo "manifest must contain exactly one SHA-256 for $asset_name" >&2
  exit 1
fi
expected="$mapfile_compat"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$asset" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$asset" | awk '{print $1}')"
fi
if [[ "$actual" != "$expected" ]]; then
  echo "checksum mismatch for $asset_name" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
module_copy="$work/jacsgo-candidate"
consumer="$work/consumer"
mkdir -p "$module_copy" "$consumer"
cp -R "$repo_root/jacsgo/." "$module_copy/"
rm -rf "$module_copy/build"
mkdir -p "$module_copy/build"
cp "$asset" "$module_copy/build/$library_name"

cd "$consumer"
go mod init example.invalid/jacsgo-staged-candidate-smoke
go mod edit -replace "github.com/HumanAssisted/JACS/jacsgo=$module_copy"
go get github.com/HumanAssisted/JACS/jacsgo@v0.0.0

cat > main.go <<'GO'
package main

import (
	"fmt"

	jacs "github.com/HumanAssisted/JACS/jacsgo"
)

func main() {
	algorithm := "ed25519"
	agent, _, err := jacs.EphemeralSimpleAgent(&algorithm)
	if err != nil {
		panic(err)
	}
	defer agent.Close()

	signed, err := agent.SignMessage(map[string]interface{}{
		"candidate": true,
		"action":    "approve",
	})
	if err != nil {
		panic(err)
	}
	verified, err := agent.Verify(signed.Raw)
	if err != nil {
		panic(err)
	}
	if !verified.Valid || verified.SignerID == "" {
		panic("staged external sign/verify contract did not authenticate a signer")
	}
	fmt.Printf("jacsgo staged candidate: valid=%t signer=%s\n", verified.Valid, verified.SignerID)
}
GO

go build -o jacsgo-staged-smoke .
./jacsgo-staged-smoke
