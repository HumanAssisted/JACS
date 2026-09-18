# Releasing the portable primitive

This change is source work, not a published release. The historical publication record is retained in `archive/native/release/shipped-artifacts.json`; the active matrix describes only the portable surfaces. Assign a fresh coordinated version before releasing these incompatible CLI/MCP/API changes. Never overwrite an existing registry version or treat an existing legacy artifact as this candidate.

The active Rust publication order is `jacs-core`, `jacs-mcp`, `jacs-cli`. `jacs-wasm` is packaged as `@jacs/wasm`; `jacs-mobile` remains `publish=false` and produces Android AAR/Maven and iOS XCFramework/SwiftPM bundles. Archived native/binding/backend crates are all `publish=false`; their historical workflows are inert under `archive/native/.github/workflows`.

Run `make check` and `make test`, then the browser and mobile workflow gates. A release must pass the full active source suite, dependency/license audits, full-history secret scan and package consumer checks. Rust releases build the complete three-crate candidate set before uploading, verify registry archive digests, produce SPDX SBOMs and attest durable evidence. CLI releases smoke the exact staged binary, preserve license/notices, verify checksums and attest every public release asset. WASM releases retain browser tests and npm provenance. Do not bypass these gates to reuse an already published version.

Use `scripts/release_retry.py` to plan release/retry actions without writes. Tag conventions remain `crate/vVERSION`, `cli/vVERSION`, and `wasm-vVERSION`; execution is explicit. The protected `crates-io` environment supports OIDC trusted publishing; the existing credential migration fallback applies only until its maintainers enable trusted publishers. No archive publication, tap sync, PyPI, native npm binding or Go release runs from the active workflows.

Mobile CI artifacts are review candidates. Distribution to an app store, Maven registry or Swift package repository, actual HAI API deployment and mobile app integration are separate authorized steps. Physical-device biometrics and enrollment/lifecycle behavior remain release acceptance requirements beyond emulator/simulator results.

## Trusted-publishing migration

Configure the three crates.io trusted publishers for `.github/workflows/release-crate.yml` and the protected `crates-io` environment. Set `CRATES_IO_TRUSTED_PUBLISHING_ENABLED=true` only after verifying those publishers. The `CRATES_IO_TOKEN` secret is a temporary migration fallback; after a successful OIDC release, revoke the old crates.io API token and remove the secret. Keep the immutable workflow references and existing `npm@11.18.0` OIDC/provenance requirements in `.github/workflows/release-wasm.yml`. See the archived release guide for historical package publisher configuration; it does not authorize publishing archived code.
