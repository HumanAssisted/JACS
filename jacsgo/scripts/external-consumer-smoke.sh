#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
  echo "usage: $0 vX.Y.Z" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/../.." && pwd -P)"
fixture="$repo_root/binding-core/tests/fixtures/human_approved_document_v1.json"
test -f "$fixture" || { echo "missing shared public-proof fixture: $fixture" >&2; exit 1; }
export GOWORK=off

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
consumer="$work/consumer"
deploy="$work/deploy"
runtime_cwd="$work/runtime-cwd"
mkdir -p "$consumer" "$deploy" "$runtime_cwd"
cp "$script_dir/consumer-smoke/main.go" "$consumer/main.go"
cd "$consumer"

go mod init example.invalid/jacsgo-external-smoke
go get "github.com/HumanAssisted/JACS/jacsgo@${version}"
go mod vendor
go run "github.com/HumanAssisted/JACS/jacsgo/cmd/jacsgo-install@${version}" -version "$version"
case "$(go env GOOS)" in
  darwin) library_name="libjacsgo.dylib" ;;
  linux) library_name="libjacsgo.so" ;;
  *) echo "unsupported external jacsgo platform" >&2; exit 2 ;;
esac
installed_library="$consumer/vendor/github.com/HumanAssisted/JACS/jacsgo/build/$library_name"
bash "$script_dir/check-macos-install-name.sh" "$installed_library"
cp "$installed_library" "$deploy/$library_name"
cmp "$installed_library" "$deploy/$library_name"
go build -mod=vendor -o "$deploy/jacsgo-smoke" .
cd "$work"
mv "$consumer" "$work/unavailable-consumer"
test ! -e "$consumer"
bash "$script_dir/check-runtime-paths.sh" "$deploy/jacsgo-smoke" "$deploy/$library_name"
cd "$runtime_cwd"
env -i "$deploy/jacsgo-smoke" "$fixture"
