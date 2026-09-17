# Dependency and release security policy

Security CI audits every primary lockfile, rejects mutable GitHub Action tags,
scans full Git history for secrets, and checks Node, Python, Go, and Rust
dependencies. A known advisory may be ignored only with a named owner, a
bounded exposure statement, and a review date.

## Temporary advisory dispositions

| Advisory | Surface and reachability | Disposition | Owner | Review by |
|---|---|---|---|---|
| RUSTSEC-2023-0071 | The separate SurrealDB lock includes `rsa` through `jsonwebtoken` on some targets. JACS native signing has no RSA mode, and this path performs public-key JWT verification rather than network-observable RSA private-key operations. | Ignore only in the SurrealDB lock audit. Remove when upstream removes `rsa` or a constant-time release exists. | JACS storage maintainers | 2026-10-09 |
| RUSTSEC-2023-0089 (unmaintained) | `atomic-polyfill` is in the separate SurrealDB geometry/indexing graph through `heapless`; it is not cryptographic code and has no reported vulnerability. | Track upstream SurrealDB/geometry migration to `portable-atomic`; cargo-audit continues to report the warning. | JACS storage maintainers | 2026-10-09 |
| RUSTSEC-2025-0141 (unmaintained) | `bincode 2.0.1` is in SurrealDB's `surrealmx` graph. The advisory declares maintenance status and does not report an exploitable flaw. | Track SurrealDB's serialization dependency; do not add new direct bincode use. | JACS storage maintainers | 2026-10-09 |

Any new advisory fails CI. Review dates are deadlines, not automatic renewals.

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
