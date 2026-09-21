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

CRATES = tuple(CRATE_MANIFESTS)
