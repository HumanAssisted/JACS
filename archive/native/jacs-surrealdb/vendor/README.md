# Temporary source dependency backports

These three packages are complete copies of their published crates.io archives,
with the narrow changes below. They preserve their upstream licenses and public
test fixtures. `Cargo.toml.orig` and `.cargo_vcs_info.json` remain unchanged.
The normalized `Cargo.toml` files are the manifests Cargo actually builds.

The adapter's `[patch.crates-io]` table applies these copies only when building
this source checkout. Cargo does not propagate a dependency's patch table to
consumers. **These fixes are not published releases.** JACS release preparation,
packaging and publication reject these unpublished dependencies. Each vendor
manifest also sets `publish = false`. Replace these patches with compatible
upstream releases before releasing the adapter; publishing maintained forks
would be a separate decision.

## Provenance and changes

[`provenance.json`](provenance.json) records exact archive URLs and SHA-256
digests, base commits, upstream backport revisions, patch digests, and the hash
of every resulting source file. The complete diffs in [`patches/`](patches/)
reconstruct these directories from the archives, including test lockfiles.
The original archive checksums are:

| Package | Archive SHA-256 |
| --- | --- |
| jsonwebtoken 10.4.0 | `eba32bfb4ffdeaca3e34431072faf01745c9b26d25504aa7a6cf5684334fc4fc` |
| object_store 0.13.2 | `622acbc9100d3c10e2ee15804b0caa40e55c933d5aa53814cd520805b7958a49` |
| wasmtimer 0.4.3 | `1c598d6b99ea013e35844697fc4670d08339d5cda15588f193c6beedd12f644b` |

`object_store` raises only its optional `quick-xml` requirement from 0.39 to
0.41, following upstream commit
[`fd44ebb9`](https://github.com/apache/arrow-rs-object-store/commit/fd44ebb9c1158660795ec22d7b11acf31c3fe113).
Its 0.13 API and source code remain unchanged. A direct 0.14 update cannot meet
SurrealDB's 0.13 requirement. This removes RUSTSEC-2026-0194 and
RUSTSEC-2026-0195 from the graph.

`jsonwebtoken` upgrades its RustCrypto P-256/P-384 dependencies to 0.14 and
requires the fixed `crypto-bigint` 0.7.10. Its ECDSA adapter follows
[upstream PR #551](https://github.com/Keats/jsonwebtoken/pull/551), pinned for
review to commit
[`3739623a`](https://github.com/jh247247/jsonwebtoken/commit/3739623abb1d0fd4d87ca7a517ddcc3310307e2d).
The public `signature` 2 API bridges to the backend's `signature` 3 traits;
signatures retain the JWS fixed-width `r || s` encoding. PKCS#8 decoding uses
the updated P-256/P-384 trait, and public points retain uncompressed SEC1
encoding. No curve arithmetic is changed. This removes the old
`crypto-bigint` 0.5 family and RUSTSEC-2026-0387 from the graph.

That upstream patch targets jsonwebtoken 11, which cannot satisfy SurrealDB's
10.x requirement. The backport also includes its prerequisite explicit HMAC
`reset` feature from upstream commit
[`b5d9c38e`](https://github.com/Keats/jsonwebtoken/commit/b5d9c38ed39a5c3883f9084ac1da87c61ed782a1).
WASM enables the appropriate JavaScript entropy features for both getrandom
0.2 and the new 0.4 dependency. The latter is optional with `rust_crypto`.
The AWS-LC backend, EdDSA and RSA implementations remain unchanged.

`wasmtimer` removes its unmaintained pin-utils dependency following
[RUSTSEC-2026-0441's migration guidance](https://rustsec.org/advisories/RUSTSEC-2026-0441.html).
This is a local backport, not a merged upstream change. `Timeout<F>` uses
`pin-project-lite` for structural projection, preserving support for `!Unpin`
futures and polling the future before its deadline. `Interval` uses standard
`Pin::new` for its already-Unpin `Sleep` field. Timer scheduling, public APIs
and the original MIT license are unchanged. The dependency was already in the
SurrealDB graph; its adapter lock changes only wasmtimer's source and removes
pin-utils. The vendor's separate test lock is refreshed, including the old
futures-util version that also depended on pin-utils.

Each vendor is an independent Cargo workspace. Its checked-in test lockfile
was refreshed and audited so CI can reproduce upstream tests without relying
on the adapter's different dependency graph. The only existing vulnerability
exception is RSA's RUSTSEC-2023-0071, governed by the repository security policy:
native SurrealDB uses AWS-LC, and upstream vendor RSA tests use public synthetic
fixtures. No new advisory ID is suppressed.

## Verification

From the repository root, the focused checks retained in CI are:

```sh
cargo test --locked --manifest-path archive/native/jacs-surrealdb/vendor/jsonwebtoken/Cargo.toml --no-default-features --features rust_crypto,use_pem --test lib ecdsa::
cargo test --locked --manifest-path archive/native/jacs-surrealdb/vendor/jsonwebtoken/Cargo.toml --no-default-features --features aws_lc_rs,use_pem --test lib ecdsa::
cargo test --locked --manifest-path archive/native/jacs-surrealdb/vendor/jsonwebtoken/Cargo.toml --no-default-features --features rust_crypto,use_pem --test backport_ecdsa
cargo test --locked --manifest-path archive/native/jacs-surrealdb/vendor/jsonwebtoken/Cargo.toml --no-default-features --features aws_lc_rs,use_pem --test backport_ecdsa
cargo check --locked --manifest-path archive/native/jacs-surrealdb/vendor/jsonwebtoken/Cargo.toml --target wasm32-unknown-unknown --no-default-features --features rust_crypto --lib
cargo test --locked --manifest-path archive/native/jacs-surrealdb/vendor/object_store/Cargo.toml --all-features --lib deserde_
cargo test --locked --manifest-path archive/native/jacs-surrealdb/vendor/object_store/Cargo.toml --all-features --lib to_xml
cargo test --locked --manifest-path archive/native/jacs-surrealdb/vendor/object_store/Cargo.toml --all-features --lib test_delegated_key_response
cargo check --locked --manifest-path archive/native/jacs-surrealdb/Cargo.toml --target wasm32-unknown-unknown -p wasmtimer
cd archive/native/jacs-surrealdb/vendor/wasmtimer
wasm-pack test --node . --locked --all-features --test web --test backport_pin
```

The added ECDSA tests verify independent RFC 6979 Appendix A.2.5/A.2.6
ES256/ES384 vectors, both high-S and low-S signatures, tampering and invalid
length rejection, signature widths, and independently decoded P-384 JWK
coordinates. The same tests run against both backends. These vectors and all
upstream fixture private keys are public test material. The wasmtimer check
executes all 24 upstream WASM tests plus five added pinning regressions in
Node: address stability, completion, expiry, cancellation/drop, ready-future
precedence and ownership through getters/`into_inner`. Its independent lock
uses wasm-bindgen 0.2.128; wasm-pack selects the matching test runner. The
timer-only check separately validates the adapter's exact production lock
(including wasm-bindgen 0.2.126) without compiling SurrealDB.

Local validation also ran the complete RustCrypto suite, the AWS-LC integration
suite, RustCrypto without PEM, all 189 available object_store library tests
(four upstream tests ignored), and all 37 JACS SurrealDB conformance/storage
tests before the wasmtimer follow-up. The object_store published archive includes its inline library tests;
its separately declared `tests/get_range_file.rs` was not included upstream,
so use `--lib` for this vendored copy. Security CI audits the adapter and all
vendor test lockfiles; cargo-deny checks the adapter's resolved licenses and
advisories. JACS's notice inventory includes these path dependencies as
third-party packages.

To independently reconstruct a package, download its recorded archive, verify
the archive digest, extract it into a temporary directory, then apply the
corresponding complete diff with `patch -p1` inside the extracted package.
Compare every resulting file against `source_files_sha256` in
`provenance.json`. Generated `target` directories are outside this inventory.
