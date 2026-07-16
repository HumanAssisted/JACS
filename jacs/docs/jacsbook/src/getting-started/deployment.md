# Deployment Compatibility

JACS has several distribution surfaces, and they do not currently ship at the
same version or for the same targets. This page distinguishes four different
claims:

- **Source-compilable:** the repository has a build path for the target. The
  consumer may still need Rust, a C toolchain, system headers, and network
  access to dependency registries.
- **Prebuilt:** the public registry or GitHub release contained a native
  artifact for the target at the observation date.
- **CI-tested:** project CI compiled or tested source on that runner. A
  cross-compiled binary is only a build result, not a runtime test.
- **Runtime-smoked:** CI executed or imported the packaged artifact on that
  target. This is narrower than full feature testing.

The shipped rows below come from `release/shipped-artifacts.json`, observed
2026-07-11 against source `0.11.4` at `f621a99d`. Registry contents can change;
run `python3 scripts/check-release-matrix.py --online` or inspect the registry
before choosing a deployment target.

## What users could install at the review baseline

<!-- BEGIN GENERATED SHIPPED ARTIFACT MATRIX -->
| Surface | Shipped version/status | Prebuilt targets | CI/runtime evidence and limits |
|---|---|---|---|
| Rust library (`jacs`) | crates.io `0.11.3`; published | source only; no prebuilt library artifact | Full source suites run on Ubuntu and macOS release runners; other Rust targets are not implied. |
| CLI (`jacs-cli`) | crates.io and GitHub Releases `0.11.3`; published | macOS arm64; macOS x86_64; Linux x86_64 glibc; Linux arm64 glibc; Windows x86_64 | Release jobs build each listed target and run a launch smoke; cargo install remains a source build. |
| Python (`jacs`) | PyPI `0.11.3`; published | macOS arm64; macOS x86_64; Linux x86_64 manylinux_2_38; Linux arm64 manylinux_2_38; Linux x86_64 musllinux | CI runtime-smokes Linux x86_64; other wheels are build-only evidence. No Windows or arm64 musllinux wheel is recorded. |
| Node (`@hai.ai/jacs`) | npm `0.10.1`; published behind source | macOS arm64; macOS x86_64; Linux x86_64 glibc; Linux x86_64 musl; Linux arm64 glibc | Source CI runtime-smokes Node 20 on Ubuntu x86_64. Other listed native binaries are not runtime-smoked here. |
| Browser (`@jacs/wasm`) | npm unpublished; source only not published | browser source build; release package unavailable | Source CI builds wasm32 and runs Firefox plus Chromium/Playwright tests; Safari and Windows-hosted browsers are unverified. |
| Go (`github.com/HumanAssisted/JACS/jacsgo`) | Go module proxy `v0.0.0-20260613002535-44c41d103146`; pseudo version native library required | source binding; native library distribution is separate | Source CI runs Ubuntu x86_64; the observed module cannot link without a separately installed libjacsgo. |
<!-- END GENERATED SHIPPED ARTIFACT MATRIX -->

## Declared toolchain baselines

| Surface | Declared or tested baseline |
|---|---|
| Rust library, CLI, and WASM source | Rust 1.97; Edition 2024 |
| Python | Python 3.10–3.14 is declared by `pyproject.toml`; the source release workflow smoke-tests the exact wheel candidate on each version before publication. |
| Node | npm `0.10.1` does not declare an `engines.node` constraint. Current source and release workflows use Node 20, so the previous generic “Node 18+” statement was not a tested support guarantee. |
| Go | `go.mod` declares Go 1.21; CGo and a platform C toolchain are also required |

## Platform decisions

### Windows

The observed Windows prebuilt is the x86_64 CLI only. Do not infer Windows
Python or Node support from the CLI artifact: PyPI `0.11.3` has no Windows
wheel, npm `0.10.1` has no Windows `.node` binary, and the Go bindings have no
Windows CGo linker directive or native asset. The browser/WASM source may be
portable at the WebAssembly level, but no Windows browser runtime lane was
recorded.

### Linux libc and architecture

“Linux” is not one ABI:

- Python glibc wheels are tagged `manylinux_2_38`; systems with glibc older
  than 2.38 cannot use those wheels. The observed musllinux wheel is x86_64
  only.
- Node `0.10.1` ships x86_64 glibc and musl binaries, plus an arm64 glibc
  binary. It does not ship arm64 musl.
- CLI `0.11.3` ships glibc Linux x86_64 and arm64 archives. No musl CLI archive
  is recorded in the shipped inventory.
- A source build is a separate claim. It may work on additional targets when
  the required compiler, linker, libc headers, Rust dependencies, and system
  libraries are available, but that is not prebuilt support.

### Containers, Lambda, and serverless platforms

A container orchestrator does not remove the native ABI requirement. Match the
image architecture and libc to an actual wheel, `.node` file, CLI archive, or
Go shared library. For example, the observed Python musllinux wheel supports an
x86_64 Alpine-style image, while its glibc wheels require glibc 2.38 or newer.

This x86_64 example deliberately requires a prebuilt musllinux wheel instead of
silently falling back to an undocumented source build:

```dockerfile
FROM --platform=linux/amd64 python:3.12-alpine
RUN python -m pip install --only-binary=:all: "jacs==0.11.3"
ENV JACS_KEYCHAIN_BACKEND=disabled
WORKDIR /app
COPY . /app
CMD ["python", "main.py"]
```

AWS Lambda, Vercel, Cloudflare Workers, Deno, and Bun do not have dedicated
runtime-smoke lanes in the recorded matrix. Treat them as unverified. For
Lambda or another native serverless runtime, build and test a layer against
the exact runtime image and architecture; do not assume a generic Linux
artifact is ABI-compatible. Browser-only runtimes require the WASM package,
which was not published at the observation date.

For headless native environments, set `JACS_KEYCHAIN_BACKEND=disabled` and
supply key passwords through the deployment platform's secret mechanism. Do
not bake passwords or private keys into an image.

## Browser/WASM capability limits

The source-built WASM surface can create both Ed25519 and `pq2025` identities,
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
(cd jacspy && maturin develop --release)

# Node development build
(cd jacsnpm && npm ci && npm run build)

# Go native library + module
make -C jacsgo build

# Browser package
make build-wasm
```

Rust 1.97 or newer is required. Native language bindings also require their
language toolchain, a C linker, and platform system dependencies. A successful
source build on one machine does not add that target to the published-artifact
matrix.
