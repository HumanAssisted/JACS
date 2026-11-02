"""The complete crates.io publication order, independent of workspace boundaries."""

CRATE_MANIFESTS = {
    "jacs-core": "jacs-core/Cargo.toml",
    "jacs-media": "archive/native/jacs-media/Cargo.toml",
    "jacs": "archive/native/jacs/Cargo.toml",
    "jacs-binding-core": "archive/native/binding-core/Cargo.toml",
    "jacs-mcp": "jacs-mcp/Cargo.toml",
    "jacs-cli": "jacs-cli/Cargo.toml",
    "jacs-mcp-compat": "archive/native/jacs-mcp/Cargo.toml",
    "jacs-cli-compat": "archive/native/jacs-cli/Cargo.toml",
    "jacs-wasm": "jacs-wasm/Cargo.toml",
    "jacs-mobile": "jacs-mobile/Cargo.toml",
    "jacsnpm": "archive/native/jacsnpm/Cargo.toml",
    "jacspy": "archive/native/jacspy/Cargo.toml",
    "jacsgo": "archive/native/jacsgo/lib/Cargo.toml",
    "jacs-duckdb": "archive/native/jacs-duckdb/Cargo.toml",
    "jacs-postgresql": "archive/native/jacs-postgresql/Cargo.toml",
    "jacs-redb": "archive/native/jacs-redb/Cargo.toml",
    "jacs-surrealdb": "archive/native/jacs-surrealdb/Cargo.toml",
}

# Catalogued crates whose source versions stay aligned but which the current
# release neither packages nor publishes. Each value records why. A held crate's
# registry version may trail the release: registry parity exempts it, and its
# own lockfile stays out of the release candidate. Only a crate with its own
# lock can be held (STANDALONE_LOCKS in scripts/rust_release.py). No released
# crate may depend on a held one. To publish it again, follow "Held crates" in
# RELEASING.md: remove the entry and the crate's own [workspace] and [patch]
# tables, then restore its publish steps and any release-only waivers.
HELD_CRATES = {
    "jacs-surrealdb": (
        "its lock pins unpublished jsonwebtoken and object_store source backports for "
        "RUSTSEC-2026-0387, RUSTSEC-2026-0194 and RUSTSEC-2026-0195; as of 2026-11-02 "
        "no published SurrealDB release accepts fixed versions"
    ),
}

if not set(HELD_CRATES) <= set(CRATE_MANIFESTS):
    raise ValueError("held crates must be catalogued")

# Publication order for the current release.
CRATES = tuple(name for name in CRATE_MANIFESTS if name not in HELD_CRATES)
