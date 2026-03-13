#![cfg(all(not(target_arch = "wasm32"), feature = "docker"))]

//! Conformance tests for the S3 (MinIO) backend.
//!
//! These tests require Docker (testcontainers) to spin up a MinIO instance.
//!
//! ```sh
//! cargo test --features docker -- conformance_s3
//! ```
//!
//! Or use docker-compose:
//! ```sh
//! docker compose -f docker-compose.test.yml up -d
//! cargo test --features docker -- conformance_s3
//! ```

mod conformance;

use jacs::storage::MultiStorage;
use serial_test::serial;
use std::path::PathBuf;
use testcontainers::GenericImage;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;

/// Set up MinIO environment variables for the test.
fn setup_minio_env(host_port: u16) {
    // Safety: these tests run serially, so env var mutation is safe.
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "minioadmin");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "minioadmin");
        std::env::set_var("AWS_ENDPOINT", &format!("http://127.0.0.1:{}", host_port));
        std::env::set_var("AWS_ALLOW_HTTP", "true");
        std::env::set_var("AWS_REGION", "us-east-1");
        std::env::set_var("JACS_ENABLE_AWS_BUCKET_NAME", "jacs-test");
        std::env::set_var("AWS_VIRTUAL_HOSTED_STYLE_REQUEST", "false");
    }
}

/// Create the test bucket in MinIO using a raw HTTP PUT request.
async fn create_bucket(host_port: u16) {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/jacs-test", host_port);

    // MinIO accepts unauthenticated bucket creation in test mode,
    // but we include auth headers just in case.
    let _resp = client
        .put(&url)
        .header("Authorization", "AWS4-HMAC-SHA256 Credential=minioadmin")
        .send()
        .await;

    // Also try the simpler approach: just PUT with basic auth
    let _resp = client
        .put(&url)
        .basic_auth("minioadmin", Some("minioadmin"))
        .send()
        .await;

    // Give MinIO a moment to register the bucket
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
}

async fn create_s3_storage() -> MultiStorage {
    let minio = GenericImage::new("minio/minio", "latest")
        .with_exposed_port(9000.tcp())
        .with_env_var("MINIO_ROOT_USER", "minioadmin")
        .with_env_var("MINIO_ROOT_PASSWORD", "minioadmin")
        .with_cmd(vec!["server", "/data"])
        .with_wait_for(WaitFor::message_on_stderr("API:"))
        .start()
        .await
        .expect("Failed to start MinIO container");

    let host_port = minio
        .get_host_port_ipv4(9000)
        .await
        .expect("Failed to get MinIO host port");

    setup_minio_env(host_port);
    create_bucket(host_port).await;

    let tempdir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage = MultiStorage::_new("aws".to_string(), tempdir.into_path())
        .expect("Failed to create S3 MultiStorage");

    // Leak the container handle to keep it alive for the test duration
    std::mem::forget(minio);

    storage
}

storage_conformance_tests!(create_s3_storage);
