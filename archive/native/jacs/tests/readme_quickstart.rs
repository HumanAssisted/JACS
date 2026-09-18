#[allow(dead_code)]
mod compiled_example {
    include!("../examples/readme_quickstart.rs");
}

#[test]
fn rust_readme_quickstart_stays_in_sync_with_compiled_example() {
    let readme = include_str!("../README.md");
    let quickstart = readme
        .split_once("## Quick start")
        .expect("README quick-start heading")
        .1;
    let block = quickstart
        .split_once("```rust\n")
        .expect("README Rust quick-start fence")
        .1
        .split_once("\n```")
        .expect("README Rust quick-start closing fence")
        .0;
    let compiled = include_str!("../examples/readme_quickstart.rs").trim_end();
    assert_eq!(
        block, compiled,
        "README quickstart must be the compiled example"
    );
}
