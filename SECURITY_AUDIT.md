# Dependency and release security policy

Security CI audits every primary lockfile, rejects mutable GitHub Action tags,
scans full Git history for secrets, and checks Node, Python, Go, and Rust
dependencies. A known advisory may be ignored only with a named owner, a
bounded exposure statement, and a review date.

## Temporary advisory dispositions

| Advisory | Surface and reachability | Disposition | Owner | Review by |
|---|---|---|---|---|
| RUSTSEC-2023-0071 | The separate SurrealDB lock includes `rsa` through `jsonwebtoken` on some targets. JACS native signing has no RSA mode, and this path performs public-key JWT verification rather than network-observable RSA private-key operations. | Ignore only in the SurrealDB lock audit. Remove when upstream removes `rsa` or a constant-time release exists. | JACS storage maintainers | 2026-10-09 |
| PYSEC-2026-311 / GHSA-f4j7-r4q5-qw2c | `chromadb 1.1.1` is present only in the optional `crewai` adapter resolution; the two advisory IDs describe the same pre-authentication code-injection vulnerability. The JACS wheel has no runtime Python dependencies and JACS does not invoke ChromaDB. | The core and every other extra remain blocking. Ignore only for the `crewai` and aggregate `all` extra audits until CrewAI permits a patched ChromaDB. | JACS Python maintainers | 2026-08-09 |
| RUSTSEC-2023-0089 (unmaintained) | `atomic-polyfill` is in the separate SurrealDB geometry/indexing graph through `heapless`; it is not cryptographic code and has no reported vulnerability. | Track upstream SurrealDB/geometry migration to `portable-atomic`; cargo-audit continues to report the warning. | JACS storage maintainers | 2026-10-09 |
| RUSTSEC-2025-0141 (unmaintained) | `bincode 2.0.1` is in SurrealDB's `surrealmx` graph. The advisory declares maintenance status and does not report an exploitable flaw. | Track SurrealDB's serialization dependency; do not add new direct bincode use. | JACS storage maintainers | 2026-10-09 |

Any new advisory fails CI. Review dates are deadlines, not automatic renewals.

The 2026-09-08 dependency recheck retires the `json-repair` disposition: the
compatible CrewAI 1.15.6 update permits `json-repair 0.60.1`, and unsuppressed
`crewai` and `all` audits report no advisory for that package. Node lock and
packed-candidate audits, and Rust workspace and standalone-lock audits, pass
after compatible dependency updates. The existing SurrealDB dispositions above
remain unchanged.

The optional `crewai` and aggregate `all` Python resolutions remain blocked.
[CrewAI 1.15.6](https://pypi.org/pypi/crewai/1.15.6/json) still requires
`chromadb ~=1.1.0`, resolving to
[ChromaDB 1.1.1](https://pypi.org/pypi/chromadb/1.1.1/json). Unsuppressed audits
report four distinct findings with no listed fixed version: PYSEC-2026-311
(alias GHSA-f4j7-r4q5-qw2c), GHSA-2wm9-hf6c-p5cr, GHSA-36p7-vc44-83pf, and
GHSA-xph7-9rjv-w5fr. The original 2026-08-09 deadline remains expired and
blocking; no review deadline is extended and no additional advisory is ignored.
Resolving that dependency requires a separate upstream or adapter decision;
this remediation does not remove the adapter or change its behavior.

The exact secret-history allowlist is in `.gitleaksignore`; broader path or rule
allowlists are prohibited.

The two allowlisted private-key findings are deterministic public test fixtures
that remain at `jacs/tests/fixtures/keys/agent-{one,two}.private.pem`. They must
never be used as trusted identities or production credentials; the allowlist
applies only to the exact historical fingerprints, not the current paths or the
private-key detector generally.
