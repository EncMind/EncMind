# EncMind

**Open-source, self-hostable private AI assistant written in Rust.**

Deploy on any Linux VM, a home server, or a TEE-capable VM (AMD SEV-SNP, under development) for a hardened self-hosted setup. Interact via Slack, Gmail, web chat, or a local edge CLI.

*An open-source, cross-platform AI assistant built for privacy and auditability.*

---

## Why EncMind

EncMind is a security- and privacy-focused AI assistant built in Rust, inspired by [OpenClaw](https://github.com/openclaw/openclaw).

- **Single binary deployment** — one Rust binary, zero runtime dependencies
- **Compile-time memory safety** — no GC pauses, no runtime crashes
- **Security by default** — per-row encryption, hash-chained audit, egress firewall, and capability-gated skill sandbox
- **WASM skill sandbox** — fuel-metered, capability-gated, dual ABI (Rust + TypeScript)
- **Built-in memory and RAG** — hybrid search with Qdrant vectors + FTS5
- **Headless browser pool** — Chromium via CDP with upload support
- **Multi-channel** — Telegram, Slack, Gmail, web chat, local edge CLI
- **TEE integration path** — designed for TEE hardened deployments

---

## Architecture

```
┌───────────────────┐             ┌───────────────────────────────────────────┐
│  Thin EncMind     │    TLS      │  Server VM (TEE optional)                 │
│  Edge             │  ◄═══════►  │                                           │
│  (optional)       │             │  ┌─────────────────────────────────────┐  │
│                   │             │  │         Agent Runtime (Rust)        │  │
│  • File proxy     │             │  │                                     │  │
│  • Bash proxy     │             │  │  Conversation loop                  │  │
│  • Device bridge  │             │  │  Tool dispatch + approval           │  │
│  • Chat UI (CLI)  │             │  │  Context management                 │  │
│                   │             │  └──────────┬──────────────────────────┘  │
│  Rust binary      │             │             │                             │
│  macOS/Linux/Win  │             │  ┌──────────┼─────────────────────┐       │
└───────────────────┘             │  │          │          |          │       │
                                  │  ▼          ▼          ▼          ▼       │
  ┌──────────┐                    │ ┌────┐  ┌────────┐ ┌────────┐ ┌──────┐    │
  │ Web Chat │◄══════════════════►│ │Chan│  │Local   │ │Skills  │ │Memory│    │
  │ (Lit)    │         TLS        │ │nels│  │LLM     │ │(WASM)  │ │+ RAG │    │
  └──────────┘                    │ │    │  │        │ │        │ │      │    │
                                  │ │Tele│  │Llama   │ │Web     │ │Qdrant│    │
  ┌──────────┐                    │ │gram│  │Mistral │ │search  │ │      │    │
  │ Telegram │◄══════════════════►│ │Sla │  │(on VM) │ │Code    │ │Vector│    │
  │ Slack    │    Channel APIs    │ │ck  │  │        │ │File    │ │+ FTS │    │
  └──────────┘                    │ │Web │  │+ API   │ │Tasks   │ │      │    │
                                  │ │    │  │provid. │ │        │ │      │    │
                                  │ └────┘  └────────┘ └────────┘ └──────┘    │
                                  │                                           │
                                  │  ┌─────────────────────────────────────┐  │
                                  │  │  Encrypted Storage (AES-256-GCM)    │  │
                                  │  │  Sealed keys, data opaque on disk   │  │
                                  │  └─────────────────────────────────────┘  │
                                  │                                           │
                                  │  ┌─────────────────────────────────────┐  │
                                  │  │  TEE Integration Layer              │  │
                                  │  │  Provider + key-sealing hooks       │  │
                                  │  │  (attestation endpoint planned)     │  │
                                  │  └─────────────────────────────────────┘  │
                                  └───────────────────────────────────────────┘
```

### Crates

The project is organized as 15 Rust crates:

```
encmind-core        — types, traits, config, policy, hooks
encmind-tee         — TEE provider abstraction, SEV-SNP detection/hooks
encmind-storage     — SQLite, migrations, encrypted stores
encmind-llm         — LLM backends (Anthropic, OpenAI, local)
encmind-wasm-host   — Wasmtime runtime, dual ABI, host functions
encmind-agent       — conversation loop, tool dispatch, context
encmind-cli         — terminal interface, config, backup (binary: encmind-core)
encmind-crypto      — Ed25519 keypairs, pairing, nonce challenges
encmind-gateway     — axum HTTP/WS server, handlers, plugins
encmind-edge        — local device bridge, file/bash proxy (binary: encmind-edge)
encmind-memory      — embeddings, vector store, hybrid search
encmind-channels    — Telegram, Slack, Gmail adapters, routing
encmind-browser     — headless Chromium pool, CDP tools
encmind-skill-cli   — skill authoring CLI (binary: encmind-skill)
encmind-skill-sdk   — WASM skill SDK for Rust authors
```

Plus: `sdk/typescript/` (Javy skill SDK for TypeScript authors).

---

## Cloud Advantage Features

### Power features

Always-on agent, concurrent cron, encrypted backup with retention, multi-device hub, headless browser pool, cross-device memory (Qdrant), retrieval quality gate, unified timeline.

**In progress:** parallel agent pool, webhook ingestion, durable workflows. Local LLM inference (Llama/Mistral) is scaffolded but untested.

### Security features

Per-row AES-256-GCM, hash-chained audit, key rotation, egress firewall, rate limiting, per-device permissions, emergency lockdown, TLS lifecycle, process isolation, confidential-memory controls.

**Planned:** TEE attestation (AMD SEV-SNP), external vault/KMS integration.

---

## Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | Foundation + Memory/RAG | Done |
| 2 | Channels | Done |
| 3 | Skills Marketplace + Hardening | In Progress |
| 4 | Self-Hosted Models | In Progress |
| 5 | Cloud VM Features | In Progress |
| 6 | TEE + Attestation | Planned |
| 7 | NAS Devices | Planned |
| 8 | Domains with Certificates | Planned |
| 9 | Multi-Tenant Support | Planned |

Current state: 15 crates, channels (Telegram / Slack / Gmail), dual-ABI WASM skills, Qdrant RAG, auto-TLS, and browser pool support.

---

## Quick Start

### Build

```bash
cargo build --release -p encmind-cli -p encmind-edge -p encmind-skill-cli
```

This produces three binaries in `target/release/`:

| Binary | Description |
|--------|-------------|
| `encmind-core` | Server (gateway + agent + channels) |
| `encmind-edge` | Local device client |
| `encmind-skill` | Skill authoring CLI |

### Run

```bash
# Set required environment variables
export ANTHROPIC_API_KEY="YOUR_ANTHROPIC_API_KEY"
export OPENAI_API_KEY="YOUR_OPENAI_API_KEY"
export ENCMIND_PASSPHRASE="pick-a-strong-passphrase"

# Optional: only needed if using Slack
export SLACK_BOT_TOKEN="YOUR_SLACK_BOT_TOKEN"
export SLACK_APP_TOKEN="YOUR_SLACK_APP_TOKEN"

# Optional: needed only when server.public_webhooks.enabled=true
export ENCMIND_WEBHOOK_TOKEN="YOUR_WEBHOOK_BEARER_TOKEN"

# Optional: needed only if booting Gmail adapter from env credentials
export GMAIL_CLIENT_ID="YOUR_GMAIL_CLIENT_ID"
export GMAIL_CLIENT_SECRET="YOUR_GMAIL_CLIENT_SECRET"
export GMAIL_REFRESH_TOKEN="YOUR_GMAIL_REFRESH_TOKEN"

# Start the server (uses ~/.encmind/config.yaml by default)
./target/release/encmind-core serve

# Or specify a custom config path
./target/release/encmind-core --config /path/to/config.yaml serve

# Pair a local device
./target/release/encmind-edge pair
./target/release/encmind-edge connect

# Chat via CLI (open a new terminal)
./target/release/encmind-edge chat
```

### Configuration

Create `~/.encmind/config.yaml`:

```yaml
server:
  host: '127.0.0.1'
  port: 8443
  public_webhooks:
    enabled: false
    require_tls: false
    auth_mode: shared_bearer
    auth_token_env: ENCMIND_WEBHOOK_TOKEN

storage:
  db_path: ~/.encmind/data.db
  key_source:
    type: Passphrase
    passphrase_env: ENCMIND_PASSPHRASE

llm:
  mode:
    type: ApiProvider
    provider: anthropic
  api_providers:
  - name: anthropic
    model: claude-sonnet-4-20250514
  - name: openai
    model: gpt-4o

# Option A: Local embedding (private — no data leaves your server)
memory:
  enabled: true
  embedding_mode:
    type: private
  # Optional: load model files from a local directory containing
  # config.json, tokenizer.json, and model.safetensors.
  # local_model_path: /path/to/local-embedding-model
  model_name: BAAI/bge-small-en-v1.5
  embedding_dimensions: 384
  vector_backend:
    type: qdrant
    url: http://localhost:6334
    collection: encmind_memories

# Option B: External embedding (OpenAI API)
# memory:
#   enabled: true
#   embedding_mode:
#     type: external
#     provider: openai
#     api_base_url: https://api.openai.com
#   model_name: text-embedding-3-small
#   embedding_dimensions: 1536
#   vector_backend:
#     type: qdrant
#     url: http://localhost:6334
#     collection: encmind_memories

tee:
  enabled: true

channels:
  slack:
    bot_token_env: SLACK_BOT_TOKEN
    app_token_env: SLACK_APP_TOKEN
  gmail:
    client_id_env: GMAIL_CLIENT_ID
    client_secret_env: GMAIL_CLIENT_SECRET
    refresh_token_env: GMAIL_REFRESH_TOKEN
    poll_interval_secs: 30
    max_attachments_per_message: 5
    max_file_bytes: 10485760
    label_filter: UNREAD
    auto_reply: false
    allowed_senders:
      - sender_id: user@example.com
        auto_reply: true
  access_policy:
    default_action: allow

skills:
  enabled: []
  wasm_dir: ~/.encmind/skills

mcp:
  servers: []

security:
  bash_mode: ask
  egress_firewall:
    enabled: true
    mode: allow_public_internet
    global_allowlist:
      - "localhost:8080"
    block_private_ranges: false
  rate_limit:
    messages_per_minute: 30
    tool_calls_per_run: 50

agents:
  list: []

agent_pool:
  max_concurrent_agents: 8
  per_session_timeout_secs: 300

browser:
  enabled: true
  pool_size: 1
  idle_timeout_secs: 300
  no_sandbox: false
  startup_policy: best_effort
  upload_root: /tmp/encmind-uploads
  allowed_actions:
    - click
    - type
    - navigate
    - get_text

backup:
  enabled: true
  encryption: true
  retention:
    daily: 7
    weekly: 4

gateway:
  mdns_enabled: true
  default_device_permissions:
    chat: true
    file_read: true
    file_write: true
    file_list: true
    bash_exec: true
    admin: false
```

### Embedding modes

EncMind supports two embedding modes for memory/RAG:

| Mode | Config `type` | Dimensions | Privacy | Requires |
|------|--------------|------------|---------|----------|
| **Private (local)** | `private` | 384 | Full — no data leaves your server | CPU only, ~130MB model download on first use |
| **External (API)** | `external` | 1536 | Text sent to provider for embedding | `OPENAI_API_KEY` (or other provider key) |

Private mode uses `model_name` (default: `BAAI/bge-small-en-v1.5`) via [candle](https://github.com/huggingface/candle) (pure Rust, no ONNX Runtime). By default, the model is downloaded from HuggingFace Hub on first startup and cached at `~/.cache/huggingface/`. If `local_model_path` is set, EncMind loads the model from local files instead.

**Switching between modes:**

Switching embedding modes changes the vector dimensions (384 vs 1536). Existing memories stored with the old dimensions **cannot be searched** with the new embedding model — the vectors are incompatible.

To switch cleanly:

1. Change `embedding_mode`, `model_name`, `embedding_dimensions`, and `collection` in config
2. Use a **new Qdrant collection name** (e.g., `encmind_memories_local`) to avoid dimension conflicts
3. Restart the server

Old memories in the previous collection are preserved but will not appear in search results. There is currently no built-in re-embedding migration — this is a known limitation.

When switching to external mode, set `model_name` and `embedding_dimensions` explicitly for your provider.

**Private mode config:**
```yaml
memory:
  enabled: true
  embedding_mode:
    type: private
  # local_model_path: /path/to/local-embedding-model
  model_name: BAAI/bge-small-en-v1.5
  embedding_dimensions: 384
  vector_backend:
    type: qdrant
    url: http://localhost:6334
    collection: encmind_memories
```

**External mode config (OpenAI):**
```yaml
memory:
  enabled: true
  embedding_mode:
    type: external
    provider: openai
    api_base_url: https://api.openai.com
  model_name: text-embedding-3-small
  embedding_dimensions: 1536
  vector_backend:
    type: qdrant
    url: http://localhost:6334
    collection: encmind_memories
```

### Install as a system service

```bash
# Linux (systemd) or macOS (launchd)
./install.sh
```

---

## Skills

EncMind runs third-party code in a WASM sandbox with fuel metering, capability gating, and an egress firewall. Skills cannot access the host filesystem or network unless explicitly granted capabilities in their manifest.

### Supported ABIs

| ABI | Language | Capabilities |
|-----|----------|-------------|
| Native | Rust | Full: tools, timers, KV, net, hooks, transforms |
| Javy | TypeScript | Tools only, simpler authoring (WASI stdin/stdout) |

### Create a skill

```bash
# Build the skill CLI (if not already built)
cargo build --release -p encmind-skill-cli
export PATH="$PWD/target/release:$PATH"
```

**Rust:**

```bash
encmind-skill init --name my-skill --lang rust
cd my-skill
encmind-skill build .
encmind-skill test .
encmind-skill validate --manifest manifest.toml --wasm my_skill.wasm
```

**TypeScript** (requires [Javy](https://github.com/bytecodealliance/javy)):

```bash
encmind-skill init --name my-skill --lang typescript
cd my-skill
npm install
encmind-skill build .
encmind-skill test .
encmind-skill validate --manifest manifest.toml --wasm my-skill.wasm
```

### Deploy a skill

```bash
# Copy matching artifact pair (same stem)
cp <skill-stem>.wasm <skill-stem>.toml ~/.encmind/skills/
# Restart gateway to load
```

For Rust scaffolds with hyphenated names (for example `my-skill`), the build
artifact stem is normalized to underscore (`my_skill.wasm` / `my_skill.toml`).

### Manifest example

```toml
[skill]
name = "my-skill"
version = "0.1.0"
description = "A short description"
host_abi = "v1"                      # "v1" (Native Rust) or "javy" (TypeScript)

[capabilities]
net_outbound = ["api.example.com"]   # allowed outbound hosts
kv = true                            # optional per-skill key-value store
# hooks = ["before_tool_call"]       # optional native hook registration
# emit_events = ["my.event"]         # optional event emission

[tool]
name = "my_tool"
description = "What this tool does"
parameters = { type = "object", properties = { q = { type = "string" } } }

[resources]
max_fuel_per_invocation = 5_000_000
max_wall_clock_ms = 10_000
max_invocations_per_minute = 60
max_concurrent = 2
```

### Example skills

| Skill | Language | ABI | Description |
|-------|----------|-----|-------------|
| [`examples/skills/calc/`](examples/skills/calc/) | TypeScript | Javy | Calculator |
| [`examples/skills/web-watch/`](examples/skills/web-watch/) | Rust | Native | Web page monitor |
| [`examples/skills/echo-ts/`](examples/skills/echo-ts/) | TypeScript | Javy | Echo (smoke test) |
| [`examples/skills/echo-rust/`](examples/skills/echo-rust/) | Rust | Native | Echo (smoke test) |

### Runtime management

Skills and timers are managed via gateway RPC:

- `skills.list` / `skills.toggle` — list loaded skills, enable/disable
- `timers.list` / `timers.toggle` — list scheduled timers, enable/disable

---

## Plugins

EncMind includes two built-in native plugins, enabled by default:

| Plugin | Tools | README |
|--------|-------|--------|
| **NetProbe** | `netprobe_search`, `netprobe_fetch` | [crates/gateway/src/plugins/netprobe/](crates/gateway/src/plugins/netprobe/) |
| **Digest** | `digest_summarize`, `digest_url`, `digest_file`, `digest_transcribe` | [crates/gateway/src/plugins/digest/](crates/gateway/src/plugins/digest/) |

### Choose native plugin vs WASM skill

Use this decision table when adding new functionality:

| Requirement | Prefer native gateway plugin | Prefer WASM skill |
|-------------|------------------------------|-------------------|
| Trust model | First-party, fully trusted Rust code reviewed in-repo | Third-party or less-trusted code |
| Isolation need | Lower (runs in gateway process) | Higher (WASM sandbox + capability gating + fuel limits) |
| Throughput/latency sensitivity | High-throughput IO, low-latency hot path | Normal tool latency is acceptable |
| API surface needed | Needs gateway-only APIs (RPC methods, channel transforms, native timers, direct runtime resources) | Tool-style skills are enough |
| Deployment model | Compiled into gateway binary and released with server | Dropped into `~/.encmind/skills` without rebuilding gateway |

### Native plugin benefits and trade-offs

- **Security (operational):** no runtime plugin download path; code is versioned, reviewed, and shipped with the gateway binary.
- **Security (policy):** still benefits from global gateway controls (egress firewall, rate limits, auth/policy checks).
- **Performance:** no Wasmtime runtime boundary, no ABI marshalling overhead, and direct reuse of shared Rust clients/pools.
- **Trade-off:** native plugins are **not sandboxed** like WASM skills. Use native plugins only for trusted code.

### Create a native gateway plugin (compiled-in)

1. Create a plugin module, for example `crates/gateway/src/plugins/myplugin/mod.rs`.
2. Implement `NativePlugin` and register tools with `PluginRegistrar`.
3. Export the module in `crates/gateway/src/plugins/mod.rs` (`pub mod myplugin;`).
4. Wire construction into `build_native_plugins(...)` in `crates/gateway/src/server.rs`.
5. Add plugin config under `plugins.myplugin` in `~/.encmind/config.yaml` and parse it in `build_native_plugins(...)`.

Minimal skeleton:

```rust
use std::sync::Arc;
use async_trait::async_trait;
use encmind_core::error::{AppError, PluginError};
use encmind_core::plugin::{NativePlugin, PluginKind, PluginManifest, PluginRegistrar};
use encmind_core::traits::InternalToolHandler;
use encmind_core::types::{AgentId, SessionId};

pub struct MyPlugin;

#[async_trait]
impl NativePlugin for MyPlugin {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: "myplugin".into(),
            name: "My Plugin".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            description: "Example native gateway plugin".into(),
            kind: PluginKind::General,
            required: false,
        }
    }

    async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
        api.register_tool(
            "hello",
            "Return a greeting",
            serde_json::json!({
                "type": "object",
                "properties": { "name": { "type": "string" } }
            }),
            Arc::new(HelloHandler),
        )
    }
}

struct HelloHandler;

#[async_trait]
impl InternalToolHandler for HelloHandler {
    async fn handle(
        &self,
        input: serde_json::Value,
        _session_id: &SessionId,
        _agent_id: &AgentId,
    ) -> Result<String, AppError> {
        let name = input.get("name").and_then(|v| v.as_str()).unwrap_or("world");
        Ok(serde_json::json!({ "message": format!("hello, {name}") }).to_string())
    }
}
```

### Build and run with your native plugin

```bash
# Build gateway binary (and related CLIs)
cargo build --release -p encmind-cli -p encmind-edge -p encmind-skill-cli

# Start gateway
./target/release/encmind-core --config ~/.encmind/config.yaml serve
```

Check startup logs for plugin registration and tool count changes.

---

## License

MIT
