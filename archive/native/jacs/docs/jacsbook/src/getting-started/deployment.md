# Deployment Compatibility

The [release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md)
records verified 0.15.0 packages, platforms, checksums and provenance. Prebuilt,
CI-tested and runtime-tested coverage differ; source compilation alone does not
establish them. Later source changes need separate release evidence.

## Declared toolchain baselines

| Surface | Declared or tested baseline |
|---|---|
| Rust library, CLI, and WASM source | Rust 1.97; Edition 2024 |
| Python | Python 3.11–3.14 is declared by `pyproject.toml`; the source release workflow smoke-tests the exact wheel candidate on each version before publication. |
| Node | Installed native addon: Node 20+. Building with NAPI-RS CLI 3 requires Node `^20.17.0`, `^22.13.0` or `>=23.5.0`. |
| Go | `go.mod` declares Go 1.21; CGo and a platform C toolchain are also required |

## Platform decisions

### Windows

The observed Windows prebuilt is the x86_64 CLI only. Do not infer Windows
Python or Node support from the CLI artifact: PyPI `0.15.0` has no Windows
wheel, npm `0.15.0` has no Windows `.node` binary, and the Go bindings have no
Windows CGo linker directive or native asset. The browser/WASM source may be
portable at the WebAssembly level, but no Windows browser runtime lane was
recorded.

### Linux libc and architecture

“Linux” is not one ABI:

- Python glibc wheels are tagged `manylinux_2_28`; systems with glibc older
  than 2.28 cannot use those wheels. The observed musllinux wheel is x86_64
  only.
- Node `0.15.0` ships x86_64 and arm64 binaries for both glibc and musl.
- CLI `0.15.0` ships glibc Linux x86_64 and arm64 archives. No musl CLI archive
  is recorded in the shipped inventory.
- A source build is a separate claim. It may work on additional targets when
  the required compiler, linker, libc headers, Rust dependencies, and system
  libraries are available, but that is not prebuilt support.

### Containers, Lambda, and serverless platforms

A container orchestrator does not remove the native ABI requirement. Match the
image architecture and libc to an actual wheel, `.node` file, CLI archive, or
Go shared library. For example, the observed Python musllinux wheel supports an
x86_64 Alpine-style image, while its glibc wheels require glibc 2.28 or newer.

This x86_64 example deliberately requires a prebuilt musllinux wheel instead of
silently falling back to an undocumented source build:

```dockerfile
FROM --platform=linux/amd64 python:3.12-alpine
RUN python -m pip install --only-binary=:all: "jacs==0.15.0"
ENV JACS_KEYCHAIN_BACKEND=disabled
WORKDIR /app
COPY . /app
CMD ["python", "main.py"]
```

AWS Lambda, Vercel, Cloudflare Workers, Deno, and Bun do not have dedicated
runtime-smoke lanes in the recorded matrix. Treat them as unverified. For
Lambda or another native serverless runtime, build and test a layer against
the exact runtime image and architecture; do not assume a generic Linux
artifact is ABI-compatible. Browser-only runtimes require the published `@hai.ai/jacs-wasm` package.

For headless native environments, set `JACS_KEYCHAIN_BACKEND=disabled` and
supply key passwords through the deployment platform's secret mechanism. Do
not bake passwords or private keys into an image.

## Browser/WASM capability limits

The WASM surface defaults to `pq2025` identities, with explicit Ed25519 and
ES256 compatibility, and can
sign and verify JSON, and use encrypted browser persistence. It does not expose
native filesystem storage, DNS resolution, MCP, or the native CLI. Browser
WebAssembly memory is JavaScript-visible; source compatibility is not a claim
of hardware-backed key isolation. See the WASM package security caveats before
using it for long-lived signing keys.

## Building from source

Source builds require the full repository because the language bindings use
path dependencies on the Rust crates:

```bash
git clone https://github.com/HumanAssisted/JACS.git
cd JACS

# Python development build
python -m pip install maturin
make build-jacspy

# Node development build
make build-jacsnpm

# Go native library + module
make build-jacsgo

# Browser package
make build-wasm
```

Rust 1.97 or newer is required. Native language bindings also require their
language toolchain, a C linker, and platform system dependencies. A successful
source build on one machine does not add that target to the published-artifact
matrix.
