fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&jacs_mcp::contract::canonical_contract_snapshot()).unwrap()
    );
}
