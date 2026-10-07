# Go library

The published module is `github.com/HumanAssisted/JACS/jacsgo@v0.15.0`.
It requires CGo, a C toolchain and the version-matched shared library.
In a module that imports `github.com/HumanAssisted/JACS/jacsgo`:

```sh
go get github.com/HumanAssisted/JACS/jacsgo@v0.15.0
go mod vendor
go run github.com/HumanAssisted/JACS/jacsgo/cmd/jacsgo-install@v0.15.0 -version v0.15.0
```

The installer verifies the native library's checksum and places it in the
vendored module. Build with `CGO_ENABLED=1` and deploy the matching shared
library alongside the executable, as described in the
[current Go guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacsgo/README.md).
macOS arm64/x86_64 and glibc Linux arm64/x86_64 libraries are released;
Windows and musl prebuilt libraries are unavailable.

See the [Go API and quickstart](native/go/installation.html), using the current
version and installation contract above. `go get` alone does not install the
native library needed for linking and execution.
