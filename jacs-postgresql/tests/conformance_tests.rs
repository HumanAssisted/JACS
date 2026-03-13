//! Conformance tests for the PostgreSQL backend using JACS conformance macros.
//!
//! These tests require Docker (testcontainers) to spin up an ephemeral
//! PostgreSQL instance. A single container is shared across all conformance
//! tests (since they run with `#[serial]`), avoiding the resource leak from
//! creating one container per test via `mem::forget`.
//!
//! ```sh
//! cargo test -p jacs-postgresql -- conformance
//! ```

use jacs::storage::database_traits::DatabaseDocumentTraits;
use jacs_postgresql::PostgresStorage;
use serial_test::serial;
use testcontainers::ContainerAsync;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use tokio::sync::OnceCell;

/// Shared container + connection URL. The `OnceCell` is initialized on the
/// first test; subsequent tests reuse the same container. The container is
/// dropped when the test binary exits.
static SHARED: OnceCell<(ContainerAsync<Postgres>, String)> = OnceCell::const_new();

async fn shared_container() -> &'static (ContainerAsync<Postgres>, String) {
    SHARED
        .get_or_init(|| async {
            let container = Postgres::default()
                .start()
                .await
                .expect("Failed to start PostgreSQL container");

            let host_port = container
                .get_host_port_ipv4(5432)
                .await
                .expect("Failed to get host port");

            let url = format!(
                "postgres://postgres:postgres@127.0.0.1:{}/postgres",
                host_port,
            );

            (container, url)
        })
        .await
}

async fn create_postgres_storage() -> PostgresStorage {
    let (_container, url) = shared_container().await;

    let db = PostgresStorage::new(url, Some(5), Some(1), Some(30))
        .expect("Failed to create PostgresStorage");

    db.run_migrations()
        .expect("Failed to run database migrations");

    // Truncate the table between tests so document counts are deterministic.
    // Uses a separate short-lived pool since PostgresStorage.pool is private.
    // Ignoring errors: table may not exist on the first run (before migrations).
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .expect("Failed to connect for cleanup");
    let _ = sqlx::query("TRUNCATE TABLE jacs_document")
        .execute(&pool)
        .await;

    db
}

// Use the JACS conformance test macros.
// These macros bring in `make_test_doc` from `jacs::testing`.
jacs::storage_conformance_tests!(create_postgres_storage);
jacs::database_conformance_tests!(create_postgres_storage);
