// EncMind Skill: Echo (Rust / Native ABI)
//
// Demonstrates the Rust SDK macro that exports:
//   - __encmind_alloc(size: i32) -> i32
//   - __encmind_invoke(ptr: i32, len: i32) -> i64
//
// Build:
//   cargo build --release --target wasm32-unknown-unknown
//   # or: encmind-skill build .

fn handle(input: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "result": format!("echo: {}", serde_json::to_string(&input).unwrap_or_default())
    })
}

encmind_skill_sdk::export_tool!(handle);
