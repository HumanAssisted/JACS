#![cfg(all(not(target_arch = "wasm32"), feature = "database-tests"))]

//! Conformance tests for the PostgreSQL backend.
//!
//! These tests require Docker (testcontainers) to spin up an ephemeral
//! PostgreSQL instance.
//!
//! ```sh
//! cargo test --features database-tests -- conformance_postgres
//! ```

mod conformance;

use jacs::storage::database::DatabaseStorage;
use jacs::storage::database_traits::DatabaseDocumentTraits;
use serial_test::serial;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

/// Shared container handle — kept alive by each test via the returned tuple.
/// We return the storage and the container handle so the container stays alive.
static CONTAINER: std::sync::OnceLock<tokio::sync::Mutex<Option<(DatabaseStorage, Box<dyn std::any::Any + Send>)>>> =
    std::sync::OnceLock::new();

async fn create_postgres_storage() -> DatabaseStorage {
    let container = Postgres::default()
        .start()
        .await
        .expect("Failed to start PostgreSQL container");

    let host_port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Failed to get host port");

    let database_url = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        host_port
    );

    let db = DatabaseStorage::new(&database_url, Some(5), Some(1), Some(30))
        .expect("Failed to create DatabaseStorage");

    db.run_migrations()
        .expect("Failed to run database migrations");

    // Leak the container handle to keep it alive for the test duration.
    // Each test gets its own container since we use #[serial].
    std::mem::forget(container);

    db
}

storage_conformance_tests!(create_postgres_storage);
database_conformance_tests!(create_postgres_storage);
