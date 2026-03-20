use std::fs;
use std::path::Path;

use crate::manifest_utils::validate_skill_name;

/// Scaffold a new skill project with the given name and language template.
pub fn run_init(name: &str, lang: &str) -> Result<(), String> {
    validate_skill_name(name)?;

    let dir = Path::new(name);
    if dir.exists() {
        return Err(format!("directory '{name}' already exists"));
    }

    match lang {
        "rust" => scaffold_rust(name, dir),
        "typescript" | "ts" => scaffold_typescript(name, dir),
        other => Err(format!(
            "unsupported language: {other}; expected 'rust' or 'typescript'"
        )),
    }
}

fn scaffold_rust(name: &str, dir: &Path) -> Result<(), String> {
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).map_err(|e| format!("failed to create directory: {e}"))?;

    // Cargo.toml
    let cargo_toml = format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"
"#
    );
    fs::write(dir.join("Cargo.toml"), cargo_toml)
        .map_err(|e| format!("failed to write Cargo.toml: {e}"))?;

    // Manifest
    let manifest = format!(
        r#"[skill]
name = "{name}"
version = "0.1.0"
description = "A new EncMind skill"

[capabilities]
net_outbound = []
kv = false

[tool]
name = "{name}"
description = "TODO: describe what this tool does"
"#
    );
    fs::write(dir.join("manifest.toml"), manifest)
        .map_err(|e| format!("failed to write manifest.toml: {e}"))?;

    // lib.rs
    let lib_rs = "// EncMind Skill: entry point\n\
//\n\
// Required exports:\n\
//   __encmind_alloc(size: i32) -> i32   -- allocate guest memory\n\
//   __encmind_invoke(ptr: i32, len: i32) -> i64  -- handle tool invocation\n\
//\n\
// The invoke function receives a JSON payload and must return a fat pointer\n\
// (high 32 bits = ptr, low 32 bits = len) to a JSON response.\n\
\n\
use std::alloc::{alloc, Layout};\n\
\n\
#[no_mangle]\n\
pub extern \"C\" fn __encmind_alloc(size: i32) -> i32 {\n\
    let layout = Layout::from_size_align(size as usize, 1).unwrap();\n\
    unsafe { alloc(layout) as i32 }\n\
}\n\
\n\
#[no_mangle]\n\
pub extern \"C\" fn __encmind_invoke(ptr: i32, len: i32) -> i64 {\n\
    let input = unsafe {\n\
        let slice = std::slice::from_raw_parts(ptr as *const u8, len as usize);\n\
        String::from_utf8_lossy(slice).to_string()\n\
    };\n\
\n\
    let response = serde_json::json!({\"result\": format!(\"echo: {}\", input.len())}).to_string();\n\
    let bytes = response.into_bytes();\n\
    let out_ptr = __encmind_alloc(bytes.len() as i32);\n\
    unsafe {\n\
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr as *mut u8, bytes.len());\n\
    }\n\
\n\
    // Fat pointer: high 32 = ptr, low 32 = len\n\
    ((out_ptr as i64) << 32) | (bytes.len() as i64)\n\
}\n";
    fs::write(src_dir.join("lib.rs"), lib_rs)
        .map_err(|e| format!("failed to write src/lib.rs: {e}"))?;

    println!("Created Rust skill project: {name}/");
    println!("  {name}/Cargo.toml");
    println!("  {name}/manifest.toml");
    println!("  {name}/src/lib.rs");
    println!("\nBuild with: encmind-skill build {name}");
    Ok(())
}

fn scaffold_typescript(name: &str, dir: &Path) -> Result<(), String> {
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).map_err(|e| format!("failed to create directory: {e}"))?;

    // Manifest — use Javy ABI
    let manifest = format!(
        r#"[skill]
name = "{name}"
version = "0.1.0"
description = "A new EncMind skill"
host_abi = "javy"

[capabilities]
net_outbound = []
kv = false

[tool]
name = "{name}"
description = "TODO: describe what this tool does"
"#
    );
    fs::write(dir.join("manifest.toml"), manifest)
        .map_err(|e| format!("failed to write manifest.toml: {e}"))?;

    // index.ts — SDK-style registration via local runtime bridge.
    let index_ts = r#"import { registerTool } from "./runtime.js";

interface ToolInput {
  message?: string;
  [key: string]: unknown;
}

registerTool((input: ToolInput) => {
  return {
    result: `echo: ${JSON.stringify(input)}`,
  };
});
"#;
    fs::write(src_dir.join("index.ts"), index_ts)
        .map_err(|e| format!("failed to write src/index.ts: {e}"))?;

    // runtime.ts — minimal SDK-style Javy bridge with structured runtime errors.
    let runtime_ts = r#"/// <reference path="./javy.d.ts" />

// Note: single underscore — "__encmind" (double) triggers a QuickJS bug in Javy 3.0.
const RUNTIME_ENVELOPE_KEY = "_encmind";
const RUNTIME_ERROR_KEY = "runtime_error";
const MAX_STDIN_BYTES = 16 * 1024 * 1024; // 16 MiB (must match host limit)

let handler: ((input: unknown) => unknown) | null = null;

function writeJson(value: unknown): void {
  const json = JSON.stringify(value);
  if (json === undefined) {
    throw new Error("handler returned a non-JSON-serializable value");
  }
  Javy.IO.writeSync(1, new TextEncoder().encode(json));
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function writeRuntimeError(message: string): void {
  writeJson({
    [RUNTIME_ENVELOPE_KEY]: {
      [RUNTIME_ERROR_KEY]: message,
    },
  });
}

function readAll(fd: number): Uint8Array {
  const chunkSize = 8192;
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const chunk = new Uint8Array(chunkSize);
    const read = Javy.IO.readSync(fd, chunk);
    if (
      typeof read !== "number" ||
      read < 0 ||
      read > chunkSize ||
      (read | 0) !== read
    ) {
      throw new Error(`Javy.IO.readSync returned invalid byte count: ${read}`);
    }
    if (read === 0) {
      break;
    }
    if (total + read > MAX_STDIN_BYTES) {
      throw new Error(`stdin payload too large: ${total + read} bytes (max ${MAX_STDIN_BYTES})`);
    }
    const slice = read === chunkSize ? chunk : chunk.slice(0, read);
    chunks.push(slice);
    total += read;
  }

  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function main(): void {
  try {
    if (!handler) {
      writeRuntimeError("no handler registered");
      return;
    }
    const inputBytes = readAll(0);
    const input = JSON.parse(new TextDecoder().decode(inputBytes));
    const output = handler(input);
    if (output instanceof Promise) {
      throw new Error("Async tool handlers are not supported in WASM skills");
    }
    writeJson(output);
  } catch (err) {
    writeRuntimeError(errorMessage(err));
  }
}

export function registerTool(nextHandler: (input: unknown) => unknown): void {
  handler = nextHandler;
  main();
}
"#;
    fs::write(src_dir.join("runtime.ts"), runtime_ts)
        .map_err(|e| format!("failed to write src/runtime.ts: {e}"))?;

    // javy.d.ts — type declarations for Javy runtime
    let javy_dts = r#"// Type declarations for the Javy WASM runtime.
// These are provided by the Javy environment at runtime.

declare namespace Javy {
  namespace IO {
    /**
     * Read bytes into `buffer` from a file descriptor.
     * Returns the number of bytes read (0 = EOF).
     */
    function readSync(fd: number, buffer: Uint8Array): number;
    /** Write bytes to a file descriptor (1 = stdout, 2 = stderr). */
    function writeSync(fd: number, data: Uint8Array): void;
  }
}
"#;
    fs::write(src_dir.join("javy.d.ts"), javy_dts)
        .map_err(|e| format!("failed to write src/javy.d.ts: {e}"))?;

    // tsconfig.json
    let tsconfig = r#"{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ES2020",
    "strict": true,
    "outDir": "dist",
    "declaration": true
  },
  "include": ["src/**/*.ts"]
}
"#;
    fs::write(dir.join("tsconfig.json"), tsconfig)
        .map_err(|e| format!("failed to write tsconfig.json: {e}"))?;

    // package.json
    let package_json = format!(
        r#"{{
  "name": "{name}",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {{
    "build": "tsc"
  }},
  "devDependencies": {{
    "typescript": "^5.0.0"
  }}
}}
"#
    );
    fs::write(dir.join("package.json"), package_json)
        .map_err(|e| format!("failed to write package.json: {e}"))?;

    println!("Created TypeScript skill project: {name}/");
    println!("  {name}/manifest.toml");
    println!("  {name}/package.json");
    println!("  {name}/tsconfig.json");
    println!("  {name}/src/index.ts");
    println!("  {name}/src/runtime.ts");
    println!("  {name}/src/javy.d.ts");
    println!("\nNext:");
    println!("  cd {name} && npm install");
    println!("\nBuild with: encmind-skill build {name}");
    println!("Note: TypeScript build requires 'javy' to be installed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn scaffold_rust_project() {
        let tmp = TempDir::new().unwrap();
        let name = "test-skill";
        let dir = tmp.path().join(name);

        // Run init by calling scaffold_rust directly with the target dir
        scaffold_rust(name, &dir).unwrap();

        assert!(dir.join("Cargo.toml").exists());
        assert!(dir.join("manifest.toml").exists());
        assert!(dir.join("src/lib.rs").exists());

        let cargo = fs::read_to_string(dir.join("Cargo.toml")).unwrap();
        assert!(cargo.contains(r#"name = "test-skill""#));
        assert!(cargo.contains(r#"crate-type = ["cdylib"]"#));

        let manifest = fs::read_to_string(dir.join("manifest.toml")).unwrap();
        assert!(manifest.contains(r#"name = "test-skill""#));
    }

    #[test]
    fn scaffold_typescript_project() {
        let tmp = TempDir::new().unwrap();
        let name = "ts-skill";
        let dir = tmp.path().join(name);

        scaffold_typescript(name, &dir).unwrap();

        assert!(dir.join("manifest.toml").exists());
        assert!(dir.join("package.json").exists());
        assert!(dir.join("tsconfig.json").exists());
        assert!(dir.join("src/index.ts").exists());
        assert!(dir.join("src/runtime.ts").exists());

        let manifest = fs::read_to_string(dir.join("manifest.toml")).unwrap();
        assert!(manifest.contains(r#"name = "ts-skill""#));
        assert!(manifest.contains(r#"host_abi = "javy""#));
        assert!(manifest.contains("net_outbound = []"));
        let package_json = fs::read_to_string(dir.join("package.json")).unwrap();
        assert!(package_json.contains("\"typescript\""));
        let index = fs::read_to_string(dir.join("src/index.ts")).unwrap();
        assert!(index.contains("registerTool"));
        let runtime = fs::read_to_string(dir.join("src/runtime.ts")).unwrap();
        assert!(runtime.contains("const RUNTIME_ENVELOPE_KEY = \"_encmind\""));
        assert!(runtime.contains("runtime_error"));
        assert!(runtime.contains("const MAX_STDIN_BYTES = 16 * 1024 * 1024"));
    }

    #[test]
    fn init_rejects_unsupported_lang() {
        let result = run_init("whatever", "python");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported language"));
    }

    #[test]
    fn init_rejects_existing_directory() {
        let tmp = TempDir::new().unwrap();
        let original_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        fs::create_dir_all("existing-skill").unwrap();
        let result = run_init("existing-skill", "rust");
        std::env::set_current_dir(original_cwd).unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn init_rejects_path_traversal_skill_name() {
        let result = run_init("../evil", "rust");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid skill name"));
    }
}
