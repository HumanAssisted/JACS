# Dependency and release security policy

Security CI audits every primary lockfile, rejects mutable GitHub Action tags,
scans full Git history for secrets, and checks Node, Python, Go, and Rust
dependencies. A known advisory may be ignored only with a named owner, a
bounded exposure statement, and a review date.

## Temporary advisory dispositions

| Advisory | Surface and reachability | Disposition | Owner | Review by |
|---|---|---|---|---|
| RUSTSEC-2023-0071 | The separate SurrealDB lock includes `rsa 0.9.10` through `jsonwebtoken` for WASM; native targets use AWS-LC. The in-memory JACS adapter does not invoke JWT authentication or RSA private-key operations. The vendored JWT test lock exercises RSA against public upstream fixtures only. | Ignore only in the SurrealDB lock and its exact `vendor/jsonwebtoken/Cargo.lock` audit. Remove when upstream removes `rsa` or a constant-time release exists. | JACS storage maintainers | 2026-11-26 |
| RUSTSEC-2023-0089 (unmaintained) | `atomic-polyfill` is in the separate SurrealDB geometry/indexing graph through `heapless` for embedded targets; it is absent from the native Linux build and has no reported vulnerability. | Track upstream SurrealDB/geometry migration to `portable-atomic`; cargo-audit continues to report the warning. | JACS storage maintainers | 2026-11-26 |
| RUSTSEC-2025-0141 (unmaintained) | `bincode 2.0.1` is required by SurrealDB's `surrealmx 0.27.0` persistence code. The JACS adapter opens only an in-memory database without a persistence path. The advisory reports maintenance status, not an exploitable flaw. | Track SurrealDB's serialization dependency; do not add new direct bincode use. | JACS storage maintainers | 2026-11-26 |

Any new advisory fails CI. Review dates are deadlines, not automatic renewals.

The 2026-10-27 review checked these dispositions against the upgraded SurrealDB
3.3.4 graph and renewed them for 30 days. The upstream RustSec advisories for
[RSA](https://github.com/RustSec/advisory-db/blob/main/crates/rsa/RUSTSEC-2023-0071.md),
[atomic-polyfill](https://github.com/RustSec/advisory-db/blob/main/crates/atomic-polyfill/RUSTSEC-2023-0089.md),
and [bincode](https://github.com/RustSec/advisory-db/blob/main/crates/bincode/RUSTSEC-2025-0141.md)
still list no patched release. `cargo tree --locked --all-features --target
x86_64-unknown-linux-gnu` for `jacs-surrealdb/Cargo.toml` contains neither `rsa`
nor `atomic-polyfill`; `bincode` remains through `surrealmx`, `surrealdb-kvs-mem`,
`surrealdb-kvs-any`, and `surrealdb-core`. Source inspection confirmed that the
adapter uses `Surreal::new::<Mem>(())`, exposes no JWT authentication operations,
and configures no persistence path. SurrealMX's bincode calls are confined to
its persistence module. The complete lock still contains all three packages,
so the existing archive-only audit waiver and exact-parent checks remain.
Recheck these assumptions if the backend, targets, authentication, or
persistence configuration changes; this review does not claim the RSA flaw is
fixed or waive any new advisory.

### Source backports and release blockers after the 2026-10-27 updates

The SurrealDB source lock removes the following vulnerable transitive versions
using narrow backports to two vendored dependencies. Their original licenses,
upstream tests and source provenance are retained in `jacs-surrealdb/vendor`.
No new advisory exception has been added.

| Removed dependency | Advisory | Source fix |
|---|---|---|
| `crypto-bigint 0.5.5` | RUSTSEC-2026-0387 | Backport the P-256/P-384 0.14 migration from jsonwebtoken PR #551 to compatible jsonwebtoken 10.4.0, preserving its public signature traits. The source lock now uses `crypto-bigint 0.7.10`. Upgrading to the published jsonwebtoken 11.1 alone would not fix this path. |
| `quick-xml 0.39.4` | RUSTSEC-2026-0194 / RUSTSEC-2026-0195 | Backport the `quick-xml 0.41` dependency migration to compatible object_store 0.13.2 without changing SurrealDB's cloud backend API or feature set. |

The crypto path is target-specific to SurrealDB's WASM RustCrypto backend;
complete-lock audits continue to cover it even on native Linux. Existing RSA,
atomic-polyfill and bincode dispositions above remain separately enforced.

Both vendored crates retain separate, locked upstream test graphs, which CI
audits continuously. The object_store test lock has no advisory waiver. The
JWT test lock shares only the existing RSA advisory disposition and its
2026-11-26 deadline: upstream RSA regression tests use public synthetic private
keys, never service secrets. Its exact `rsa <- jsonwebtoken` parent is checked;
the waiver cannot apply to object_store or either main workspace. This extends
the reviewed RSA scope to the upstream tests without adding an ignored advisory
ID. It does not claim that RSA's timing flaw is fixed.

These path patches apply only to checkout builds. Cargo strips workspace
patches when crates are published, so a downstream registry consumer would
still resolve the vulnerable upstream versions. Rust release preparation,
packaging and publication explicitly reject these unpublished dependencies.
Compatible published fixes are required before a crates.io release can qualify;
the source backports must not be represented as already published fixes.

The same review refreshes every Python extra on Python 3.11–3.14, including the
previously unaudited development extra. Python 3.10 is no longer supported:
the patched dnspython dependency requires Python 3.11. Go candidate/release
jobs use the verified Go 1.26.10 toolchain rather than cached older 1.26 patch
releases, and the complete Go source vulnerability scan passes on that version.

The 2026-09-08 dependency recheck retired the `json-repair` disposition after a
compatible update. Node lock and packed-candidate audits, and Rust workspace and
standalone-lock audits, pass after compatible dependency updates. The SurrealDB
dispositions above remain unchanged.

On 2026-09-09 the optional `crewai` adapter and the `crewai` Python extra were
removed. CrewAI (through 1.15.20) pins `chromadb ~=1.1.0`, and the four ChromaDB
advisories (PYSEC-2026-311 / GHSA-f4j7-r4q5-qw2c, GHSA-2wm9-hf6c-p5cr,
GHSA-36p7-vc44-83pf, GHSA-xph7-9rjv-w5fr) have no patched release even at
ChromaDB 1.5.9. Rather than extend the expired 2026-08-09 exception, the
dependency was dropped: no Python resolution (core, any extra, or `all`)
contains ChromaDB, and `pip-audit` now runs unsuppressed for every extra.

## 2026-09-08 Dependabot reconciliation

The authenticated Dependabot API returned 142 open alerts against the default
branch dependency graph. Comparing every reported vulnerable range with the
locks merged through [PR #132](https://github.com/HumanAssisted/JACS/pull/132)
into `v0.11.4` found 138 patched alert instances, one removed direct dependency
(`opentelemetry_sdk` in the observability example, with patched `0.32.1` still
present transitively), and three still affected ChromaDB instances. Thus 139
of the 142 open alerts are already addressed or absent in this development
branch; this is not a claim that GitHub has closed default-branch alerts.

The remaining open alerts are [#280](https://github.com/HumanAssisted/JACS/security/dependabot/280),
[#281](https://github.com/HumanAssisted/JACS/security/dependabot/281), and
[#282](https://github.com/HumanAssisted/JACS/security/dependabot/282).
The three ChromaDB alerts, and the additional `pip-audit` finding PYSEC-2026-311,
are resolved by the 2026-09-09 removal of the `crewai` extra described above.

All 18 open Dependabot pull requests target `main`. The current locks already
meet or exceed the requested versions in Node PRs #124, #126, #129, #130, #131;
Python PRs #110, #112, #114, #116, #117, #119, #122, #127, #128; and Rust PRs
#115, #118, #125. The `uuid` dependency requested by PR #85 is no longer present.
These pull requests were neither merged separately nor used to dismiss alerts.

This follow-up also tightens compatible minimum requirements without changing
locked distribution versions: SurrealDB `3.2.1` excludes the versions covered
by [GHSA-66r2-5gwj-gxm2](https://github.com/advisories/GHSA-66r2-5gwj-gxm2) and
[GHSA-848m-r628-vrxw](https://github.com/advisories/GHSA-848m-r628-vrxw);
published Python extras require LangChain `1.3.9`, Starlette `1.3.1`, and Pillow
`12.3.0`; development/CI-only uv constraints require LangSmith `0.8.18` and
python-multipart `0.0.31`. The supported Python range and optional integrations
are preserved. Those uv constraints do not become published transitive pins.

The last security workflow on the PR head, [run 34257901360](https://github.com/HumanAssisted/JACS/actions/runs/34257901360),
passed Node and Go but failed the expired ChromaDB exception policy and the
CrewAI Python audit. Later steps in those failing jobs were skipped. The merge
was development consolidation only; it did not make those checks green or
authorize a release.

## Secret-history allowlist

The exact secret-history allowlist is in `.gitleaksignore`; broader path or rule
allowlists are prohibited.

The two allowlisted private-key findings are deterministic public test fixtures
that remain at `jacs/tests/fixtures/keys/agent-{one,two}.private.pem`. They must
never be used as trusted identities or production credentials; the allowlist
applies only to the exact historical fingerprints, not the current paths or the
private-key detector generally.

The 2026-10-27 source backports also retain public upstream JWT test keys and
tokens, object_store's synthetic test credentials and documentation placeholders.
Their bytes were checked against the checksum-verified published archives; the
backport provenance records every source-file digest. The secret scan additionally
matches ECDSA type names and those SHA-256 digests as generic API keys. The 51
reviewed findings at commit `76998c7aac2459b906e47a16d02326bbdcff5b54` are
allowlisted by exact historical fingerprint only. No fixture may be used as a
trusted credential, and no path or detector has been excluded.
