# Dependency security policy

Primary Rust, Python, Node, and Go dependency graphs are audited. A known advisory may be ignored only with a named owner, a bounded exposure statement, and a review date.

## Temporary advisory dispositions

| Advisory | Surface and reachability | Disposition | Owner | Review by |
|---|---|---|---|---|
| RUSTSEC-2023-0071 | The separate SurrealDB lock includes `rsa` through `jsonwebtoken` on some targets. JACS native signing has no RSA mode, and this path performs public-key JWT verification rather than network-observable RSA private-key operations. | Ignore only in the SurrealDB lock audit. Remove when upstream removes `rsa` or a constant-time release exists. | JACS storage maintainers | 2026-10-09 |
| PYSEC-2026-311 / GHSA-f4j7-r4q5-qw2c | `chromadb 1.1.1` is present only in the optional `crewai` adapter resolution; the two advisory IDs describe the same pre-authentication code-injection vulnerability. The JACS wheel has no runtime Python dependencies and JACS does not invoke ChromaDB. | The core and every other extra remain blocking. Ignore only for the `crewai` and aggregate `all` extra audits until CrewAI permits a patched ChromaDB. | JACS Python maintainers | 2026-08-09 |
| GHSA-xf7x-x43h-rpqh | `json-repair 0.25.x` is present only because the optional `crewai` extra constrains it to `~=0.25.2`; JACS does not call `json-repair`. | Ignore only for the `crewai` and aggregate `all` extra audits until CrewAI permits `json-repair >=0.60.1`. | JACS Python maintainers | 2026-08-09 |
| RUSTSEC-2023-0089 (unmaintained) | `atomic-polyfill` is in the separate SurrealDB geometry/indexing graph through `heapless`; it is not cryptographic code and has no reported vulnerability. | Track upstream SurrealDB/geometry migration to `portable-atomic`; cargo-audit continues to report the warning. | JACS storage maintainers | 2026-10-09 |
| RUSTSEC-2025-0141 (unmaintained) | `bincode 2.0.1` is in SurrealDB's `surrealmx` graph. The advisory declares maintenance status and does not report an exploitable flaw. | Track SurrealDB's serialization dependency; do not add new direct bincode use. | JACS storage maintainers | 2026-10-09 |

Any new advisory is blocking. Review dates are deadlines, not automatic renewals.
