//! `jacs-cli` library surface.
//!
//! This crate is primarily a binary (`jacs`), but a small slice of its CLI
//! definition is exposed as a library so the snapshot test in
//! `tests/cli_command_snapshot.rs` can walk the Clap `Command` tree
//! programmatically. Keeping the library tiny avoids the historical
//! "main.rs is in two build targets" warning (Issue 017 / Issue 023): the
//! binary lives at `src/main.rs`, the library lives here at `src/lib.rs`.
//!
//! The `password_bootstrap` module is re-published because `build_cli` calls
//! into `quickstart_password_bootstrap_help()` for `--help` text. No other
//! main.rs internals are exposed.

pub mod password_bootstrap;

mod cli_builder;

pub use cli_builder::build_cli;
