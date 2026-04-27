//! Cross-test support helpers (mod-tree included by `provenance_cross_language_tests.rs`).
//!
//! NOTE: cargo's test runner only includes `tests/<dir>/mod.rs` (and submodules
//! it declares) when a top-level `tests/<file>.rs` declares `mod <dir>;` — see
//! `provenance_cross_language_tests.rs`.

pub mod generate_provenance_fixtures;
