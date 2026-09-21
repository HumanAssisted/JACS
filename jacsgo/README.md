# JACS Go bindings

The public module remains `github.com/HumanAssisted/JACS/jacsgo`.
The Go source here is synchronized from the retained native compatibility API;
its Rust library builds separately from `archive/native/jacsgo/lib`.

Version 0.15.0 is a release candidate. After it is published, install the module
and its checksum-verified native library:

```sh
go get github.com/HumanAssisted/JACS/jacsgo@v0.15.0
go mod vendor
go run github.com/HumanAssisted/JACS/jacsgo/cmd/jacsgo-install@v0.15.0 -version v0.15.0
```

Place `libjacsgo.dylib` (macOS) or `libjacsgo.so` (Linux) beside the deployed
executable. The installer places the build-time library under the vendored module.
The release workflow verifies a relocated consumer with no source-tree fallback.

From the JACS repository root, build and test the local candidate with
`bash scripts/native_bindings.sh verify go`. Check [release status](../docs/release-status.md)
before expecting the candidate version to exist in registries or release assets.

When changing the compatibility Go implementation, run
`python3 scripts/native_bindings_sync_go.py` to update this public module;
CI checks the files match. No Cargo workspace member is added here.
