fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&jacs_mcp::canonical_contract_snapshot())
            .expect("canonical contract snapshot should serialize"),
    );
}
