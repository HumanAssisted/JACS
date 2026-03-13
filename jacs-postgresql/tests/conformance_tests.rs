//! Conformance tests for the PostgreSQL backend using JACS conformance macros.
//!
//! These tests require Docker (testcontainers) to spin up an ephemeral
//! PostgreSQL instance.
//!
//! ```sh
//! cargo test -p jacs-postgresql -- conformance
//! ```

use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs_postgresql::PostgresStorage;
use serial_test::serial;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

async fn create_postgres_storage() -> PostgresStorage {
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

    let db = PostgresStorage::new(&database_url, Some(5), Some(1), Some(30))
        .expect("Failed to create PostgresStorage");

    db.run_migrations()
        .expect("Failed to run database migrations");

    // Leak the container handle to keep it alive for the test duration.
    std::mem::forget(container);

    db
}

// Use the JACS conformance test macros.
// These macros bring in `make_test_doc` from `jacs::testing`.
jacs::storage_conformance_tests!(create_postgres_storage);
jacs::database_conformance_tests!(create_postgres_storage);
