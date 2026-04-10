# EncMind V2: Architecture & Implementation Plan

## At a Glance

**EncMind** is a self-hosted AI operations platform — an always-on, multi-channel agent that runs on your infrastructure with persistent memory, local embedding, and encrypted storage.

**V2 adds:**
- Streaming tool executor with parallel safe-tool execution
- 10-step tool governance pipeline (validate → risk classify → hook → permit → execute → post-hook)
- Multi-strategy context compaction (4 strategies + circuit breaker + diminishing returns)
- Coordinator + 4 role-specialized agents (Explore, Plan, Implement, Verify)
- Prompt compiler with static/dynamic cache boundary and break diagnostics
- Workspace trust boundary with immutable deny-list
- 2-stage memory retrieval (vector recall + LLM rerank with MMR diversity)
- Proactive/autonomous agent mode with tick-based pacing and safety caps
- Local GPU acceleration for side-queries, embedding, and transcription

**Implementation phases:**
- **Phase A (P0):** Runtime safety — query guard, message normalization, governance pipeline, streaming, trust boundary
- **Phase B (P1):** Cost & performance — prompt cache, compaction, hooks expansion, permission modes, memory taxonomy
- **Phase C (P2):** Multi-agent — role-specialized agents, coordinator, task system, deferred tool loading
- **Phase D (P3):** Long-term — dream memory consolidation, proactive mode, session search, agent architect

**Start reading:** [Section 3 (Architecture)](#3-target-architecture-v2) for the big picture, or [Section 5 (Implementation Plan)](#5-implementation-plan) for what to build and when.

---

## 1. Overview

EncMind is a self-hosted AI operations platform — an always-on, multi-channel, memory-rich agent that runs on your own infrastructure. It handles tasks across Telegram, Slack, Gmail, Web UI, and Edge CLI, with persistent memory, local embedding, encrypted storage, and extensible plugin/skill architecture.

This document specifies the target V2 architecture, full functionality catalog, and phased implementation plan.

---

## 2. Current State (V1 Baseline)

EncMind V1 is a 15-crate Rust workspace with:

- **Gateway server**: axum HTTP/WS, device pairing, TLS, mDNS
- **Agent runtime**: LLM loop with sequential tool execution, sliding-window context
- **Channels**: Telegram, Slack, Gmail adapters with access policy routing
- **Memory/RAG**: hybrid search (FTS5 + vector), external or local embedding (candle/bge-small-en-v1.5)
- **Storage**: encrypted SQLite with migrations, per-row AES-256-GCM
- **Plugins**: NetProbe (search + fetch), Digest (summarize + PDF + transcribe + file listing)
- **Skills**: WASM/Javy dual-ABI skill system with timers, transforms, and policy enforcement
- **Security**: egress firewall, TEE path, audit chain, key rotation, device permissions
- **Edge client**: paired device with file/bash commands over WebSocket
- **Browser**: chromiumoxide pool with navigate/screenshot/get_text
- **Cron**: scheduled jobs with semaphore-based concurrency

**V1 gaps addressed in this plan:**

| Gap | Impact |
|-----|--------|
| Local tool handler exists but lacks config-driven workspace policy | No trust boundary on local file access |
| Tools execute sequentially | Slow multi-tool operations |
| Single compaction strategy (sliding window) | Long sessions degrade quickly |
| System prompt recomputed every turn | Wasted tokens, no cache hits |
| No message validation before LLM calls | API 400 errors from malformed payloads |
| No workspace trust boundary | Untrusted projects can execute code via plugins/skills |
| No queue re-entry protection | Concurrent chat.send corrupts session state |
| No persistent task system | No coordinator/multi-agent orchestration |
| 9 hook events (including CustomEvent), sync only | Limited extensibility |
| Flat memory types | No organization for retrieval quality |
| No error recovery strategy | Transient failures surface to users |

---

## 3. Target Architecture (V2)

### 3.1 Architecture Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  EncMind V2 Server (single Rust binary)                          │
│                                                                   │
│  Layer 1: Interaction                                             │
│  ┌────────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌────────┐    │
│  │Telegram│ │Slack │ │Gmail │ │Web UI│ │ Cron │ │Webhooks│    │
│  └───┬────┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └───┬────┘    │
│      └─────────┴────────┴────────┴────────┴─────────┘           │
│                          ↓ common event protocol                  │
│  Layer 2: Session Orchestrator                                    │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Per-session query guard │ Lifecycle FSM │ Cancellation    │   │
│  │ Session title │ Away summary │ Prompt suggestions          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                          ↓                                        │
│  Layer 3: Agent Engine                                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Roles: Explore (RO) │ Plan (RO) │ Implement │ Verify     │   │
│  │ Coordinator ──→ workers (async, progress summaries)       │   │
│  │ Agent architect (user-defined roles from description)     │   │
│  │                                                           │   │
│  │ Prompt Compiler: static cache │ dynamic boundary │ diag   │   │
│  │ Behavioral governance │ Tool usage grammar │ Browser rules │   │
│  │ Compaction: 4 strategies + 2 controls │ 9-section/light   │   │
│  │ Error Recovery: withhold-recover │ retry │ circuit breaker │   │
│  │ Proactive mode: tick loop │ Sleep pacing │ focus-aware     │   │
│  └──────────────────────────────────────────────────────────┘   │
│                          ↓                                        │
│  Layer 4: Tool Runtime                                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Streaming Tool Executor                                    │   │
│  │ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌──────┐      │   │
│  │ │grep │ │fetch│ │file │ │ git │ │ LLM │ │ bash │      │   │
│  │ │(par)│ │(par)│ │(par)│ │(seq)│ │(seq)│ │(seq) │      │   │
│  │ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └──────┘      │   │
│  │ Governance: validate → risk classify → hook → permit → exec│   │
│  │ Permission explainer (concurrent side-query)               │   │
│  │ Browser guardrails: retry cap │ loop detect │ dialog dismiss│   │
│  └──────────────────────────────────────────────────────────┘   │
│                          ↓                                        │
│  Layer 5: Execution                                               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ FileExecutor: Local (direct) │ Edge (remote device)       │   │
│  │ Path policy │ Symlink protection │ Output caps │ Timeout   │   │
│  │ Large result: truncate + persist + TTL/quota               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                          ↓                                        │
│  Layer 6: Safety Plane                                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Workspace trust │ Permission modes │ Immutable deny-list  │   │
│  │ Message validation │ Hook system (27 events) │ Audit      │   │
│  │ Egress firewall │ Risk classifier (bash + file + network) │   │
│  └──────────────────────────────────────────────────────────┘   │
│                          ↓                                        │
│  Layer 7: Memory Plane                                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 4-type taxonomy │ Local embedding (384d) │ Hybrid search  │   │
│  │ 2-stage selection: recall + LLM rerank (MMR diversity)    │   │
│  │ Dream consolidation │ Session search │ Cross-device (V1)  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                          ↓                                        │
│  Layer 8: Model Gateway                                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Provider abstraction │ Circuit breaker │ Cost telemetry    │   │
│  │ BYO API key │ Hot-swap backend │ Rate limiting             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                 │
│  │ Task System │  │ Plugin Mgr │  │ Skill Host │                 │
│  │ Plan+Runtime│  │ Native+Hook│  │ WASM/Javy  │                 │
│  └────────────┘  └────────────┘  └────────────┘                 │
└─────────────────────────────────────────────────────────────────┘
       │               │                │
  ┌────▼────┐    ┌─────▼─────┐    ┌─────▼─────┐
  │  Local  │    │   Edge    │    │  Qdrant   │
  │Executor │    │  Client   │    │ (vectors) │
  │(direct) │    │ (remote)  │    │           │
  └─────────┘    └───────────┘    └───────────┘
```

### 3.2 Design Principles

1. **Streaming-first** — Every response is a stream, not a buffered result
2. **Permission gates at boundaries** — Check at tool choice, execution, AND result handling
3. **Observable operation** — Every step logged, profiled, traceable
4. **Graceful degradation** — Fail soft, cache fallback, suggest alternatives
5. **Context-based DI** — Tools receive what they need, not global state
6. **Feature-flagged DCE** — Compile out unused features via cargo features
7. **Minimal state** — Arc<RwLock<AppState>> with domain-specific stores
8. **Memoize expensive ops** — Git status, token counting, memory lookups
9. **Prompt layering** — Static (cacheable) + dynamic (per-turn) with boundary marker
10. **Multi-strategy selection** — Compaction, permissions, recovery all have multiple paths

---

## 4. Functionality Catalog

### 4.1 Local Server Mode (Enhance Existing)

**Purpose:** Strengthen the existing `LocalToolHandler` with config-driven workspace policy, trust boundaries, and parity with Edge security controls.

**Current state (A.8 shipped):** `LocalToolHandler` and `LocalToolPolicyEngine` now integrate with the workspace trust gate, enforce `BashMode::Allowlist` patterns at the dispatch layer, and expose an operator-configurable deny list layered on top of the hardcoded defaults. Symlink containment is verified by canonicalization in `validate_file_path` and locked in by two edge-case tests (existing-target escape and missing-target escape).

**Configuration:**
```yaml
security:
  bash_mode: !allowlist
    patterns: ["ls*", "git status", "echo*"]
  local_tools:
    mode: single_operator            # or isolated_agents
    bash_mode: host                  # or disabled
    base_roots:
      - /home/user/projects
    denied_paths:                    # operator additions, layered on defaults
      - /home/user/private-notes
  workspace_trust:
    trusted_paths:
      - /home/user/projects
    untrusted_default: readonly      # readonly | deny | allow
```

Hardcoded defaults (always denied regardless of operator config): `/etc/shadow`, `/etc/sudoers`, `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`, `~/.encmind`.

**LocalToolHandler governance pipeline (per call):**

1. **Workspace trust gate** — `evaluate_trust(agent.workspace, trust_config)`:
   - `Denied` → reject all commands with `ToolDenied { reason: "workspace_untrusted" }`
   - `ReadOnly` → allow `file.read`, `file.list`; reject `file.write`, `bash.exec`
   - `Trusted` / `Disabled` → proceed
2. **Bash allowlist enforcement** — if `security.bash_mode = Allowlist { patterns }` and the command is `bash.exec`, the command must match one of the patterns (prefix-glob `"ls*"` or exact `"git status"`). This is defense in depth: the runtime governance approval checker normally enforces this, but the local handler does it directly so any path that skips governance still gets gated.
3. **Per-agent policy** — merged from base allowed roots (`cwd`, `db_parent`, `temp_dir`, config `base_roots`), the agent's configured workspace, and the merged denied path list (defaults ∪ operator entries).
4. **Path containment** — `validate_file_path` canonicalizes the target first (following symlinks), then checks `starts_with` against canonicalized allowed roots. Missing path segments walk up to the nearest existing ancestor before canonicalization so `file.write` on a non-existent file still gets its real parent resolved.
5. **Dispatch** — `execute_command` via the edge-lib helper, with a configurable timeout (default 60s).

**Coexistence with Edge:** Local mode is always active (registered at startup). When a paired edge device is present, local tools are re-registered under a `local_` prefix so the canonical names (`file_read`, etc.) route to the remote device, while `local_file_read` stays available for server-local ops.

**Files:** `crates/core/src/config.rs`, `crates/gateway/src/local_tool_handler.rs`, `crates/gateway/src/local_tool_policy.rs`, `crates/local-client/src/commands.rs` (`validate_file_path`, symlink containment tests)

---

### 4.2 Streaming Tool Concurrency

**Purpose:** Run read-only tools in parallel, serialize destructive tools. Real-time progress streaming.

**Design:**
```rust
pub enum ToolStatus { Queued, Executing, Completed, Yielded }

pub struct StreamingToolExecutor {
    tools: Vec<TrackedTool>,
}

// Each tool declares safety via InternalToolHandler trait
fn is_concurrent_safe(&self) -> bool;  // default: false
```

- Safe tools (search, fetch, file read, list) run via `tokio::join!`
- Destructive tools (file write, bash, git commit) block the queue
- Per-tool `CancellationToken` (child of session token)
- Error cascade: Bash failure cancels queued sibling tools
- Progress messages yield immediately, results buffer until yielded

**Event protocol:**
```rust
pub enum ChatEvent {
    Delta(String),           // Streaming text
    ToolStart { name: String, id: String },
    ToolProgress { id: String, message: String },
    ToolComplete { id: String, result: ToolResult },
    Done { stop_reason: StopReason },
}
```

**Files:** new `crates/agent/src/streaming_executor.rs`, `crates/agent/src/runtime.rs`, `crates/core/src/traits.rs`

---

### 4.3 Multi-Strategy Context Compaction

**Purpose:** Keep long sessions (hours/days) stable. Know when to stop.

**Strategies:**

| Strategy | Trigger | Action | Cost |
|----------|---------|--------|------|
| Time-based micro | Idle gap > threshold | Clear stale tool results | Free |
| Snip compact | Token count approaching limit | Remove entire messages by count | Free |
| Auto-compact | Token near context window | LLM summarizes conversation | 1 API call |
| Memory-reuse compact | Same trigger, cheaper | Use extracted memories as summary | Cheaper |

**Controls (not strategies — they govern strategy behavior):**

| Control | Trigger | Action |
|---------|---------|--------|
| Diminishing returns | <500 tokens for 3+ turns | Stop agent loop entirely |
| Circuit breaker | 3 consecutive auto-compact failures | Disable auto-compact, fall back to snip |

```rust
pub struct CompactionController {
    consecutive_failures: u32,
    max_failures: u32,  // default: 3
    strategies: Vec<Box<dyn CompactionStrategy>>,
}
```

**Files:** new `crates/agent/src/compaction.rs`, `crates/agent/src/context.rs`

---

### 4.4 Coordinator + Async Multi-Agent

**Purpose:** Parallel research, serial synthesis. Clean context isolation.

```
Coordinator ──→ Worker 1: research API-A (async)
           ├──→ Worker 2: research API-B (async)   ← parallel
           └──→ Worker 3: research API-C (async)
                          ↓
                <task-notification> returns refined findings only
                          ↓
                Coordinator synthesizes → writes output (serial)
```

- `agents.spawn { prompt, async: true }` → returns task_id immediately
- Workers run in isolated context (no garbage polluting main conversation)
- `<task-notification>` XML injected into coordinator's next turn on completion
- Fork mode: child inherits parent message history for prompt cache sharing

**Files:** `crates/agent/src/subagent.rs`, `crates/agent/src/runtime.rs`

---

### 4.5 Task System (Dual-Track)

**Track A — Planning Tasks (persistent):**
- Stored in SQLite (`session_tasks` table)
- Fields: id, title, description, status, owner_agent_id, blocks/blocked_by
- Tools: `task_create`, `task_list`, `task_get`, `task_update`, `task_delete`
- Atomic ownership claims (agent must finish current before claiming another)

**Track B — Runtime Execution Tasks (ephemeral):**
- Tracked in gateway AppState (not persisted)
- Represent in-flight agent executions, shell commands, MCP calls
- Delta output streaming with polling
- Evicted after completion grace period
- `<task-notification>` delivery on completion

**Files:** new `crates/gateway/src/plugins/tasks/mod.rs`, `crates/storage/` (migration)

---

### 4.6 Prompt Compiler (Cache Engineering)

**Purpose:** Reduce token cost through prompt caching. Detect and report cache breaks.

```rust
pub struct PromptCache {
    sections: Vec<PromptSection>,
    dynamic_boundary_index: usize,  // Everything before is cacheable
}

pub struct PromptSection {
    name: &'static str,
    content: String,
    content_hash: u64,
    computed_at: Instant,
    ttl: Option<Duration>,
    is_dynamic: bool,
}

pub struct CacheBreakReport {
    pub section_name: &'static str,
    pub reason: String,
    pub tokens_wasted: u32,
}
```

Cache optimization patterns:
- **Deterministic tool sorting:** alphabetical, built-in first, MCP after
- **Hash-based config paths:** content hashes instead of raw file paths
- **State externalization:** move frequently-changing metadata to message attachments (~10% cache token reduction)
- **Invalidation triggers:** tool registry change, memory update, config change, TTL expiry

**Files:** `crates/agent/src/context.rs`, new `crates/agent/src/prompt_cache.rs`

---

### 4.7 Message Normalization Pipeline

**Purpose:** Prevent API 400 errors from malformed tool payloads.

Validation rules enforced before every LLM call:
- `tool_use.input` must be an object (not a string)
- `tool_result` must have matching `tool_use_id`
- No consecutive same-role messages
- Oversized tool results compressed inline

```rust
pub fn normalize_for_api(messages: &mut Vec<Message>) -> Result<(), ValidationError>;
pub fn validate_message(msg: &Message) -> Result<(), ValidationError>;
```

**Files:** `crates/agent/src/runtime.rs`, new `crates/agent/src/message_validation.rs`

---

### 4.8 Error Recovery (Withhold-and-Recover)

**Purpose:** Don't surface transient failures to users. No retry death spirals.

```rust
pub enum ApiErrorRecovery {
    PromptTooLong,      // → compact + retry
    MaxOutputTokens,    // → truncate + continue
    RateLimit,          // → backoff + retry
    ServerError,        // → backoff + retry
}

pub struct CircuitBreaker {
    failure_threshold: u32,
    reset_timeout: Duration,
    state: CircuitState,  // Closed / Open / HalfOpen
}
```

- Recoverable errors withheld internally, recovery attempted first
- Only surfaced if all recovery paths fail
- Skip stop-hooks on API errors (prevents retry death spirals)
- Circuit breaker applied to: LLM calls, MCP connections, embedding API, channel reconnects

**Files:** `crates/agent/src/runtime.rs`, new `crates/agent/src/error_recovery.rs`

---

### 4.9 Queue Re-Entry Guard

**Purpose:** Prevent session state corruption from concurrent `chat.send` calls.

```rust
pub struct QueryGuardRegistry {
    guards: Arc<RwLock<HashMap<SessionId, Arc<SessionQueryGuard>>>>,
}

pub struct SessionQueryGuard {
    active: AtomicBool,
    queue: Mutex<VecDeque<PendingQuery>>,
}
```

- Keyed by `session_id` (not global) — different sessions process independently
- Concurrent sends to the same session are serialized in FIFO order
- Guard acquired before agent loop, released on completion via RAII permit

**Two-class global scheduler:** Orthogonal to per-session FIFO, the agent pool uses a `TwoClassScheduler` (`crates/agent/src/scheduler.rs`) with `Interactive` and `Background` classes. Interactive runs (user chat from WS / channels) are served before background runs (cron, webhook triggers, timers). A `scheduler_fairness_cap` (default 4) forces one background dispatch after every N consecutive interactives so background traffic cannot starve. Classification is a parameter on `AgentPool::execute(_streaming)`; `handle_send` defaults to Interactive, and `handle_send_with_class` lets cron/webhook callers override to Background.

**Files:** `crates/gateway/src/handlers/chat.rs`, `crates/gateway/src/query_guard.rs`, `crates/agent/src/scheduler.rs`, `crates/agent/src/pool.rs`

---

### 4.10 Backpressure & Graceful Shutdown

**Purpose:** No resource leaks on disconnect. Clean shutdown under load.

- WebSocket handler respects TCP backpressure (bounded message buffer)
- Per-tool `CancellationToken` — client disconnect cancels in-flight tools
- Graceful drain on shutdown: wait for active tool executions, then close connections
- Configurable per-tool execution timeout (default 30s)

**Files:** `crates/gateway/src/ws.rs`, `crates/agent/src/runtime.rs`

---

### 4.11 Workspace Trust Boundary

**Purpose:** Prevent code execution from untrusted workspace directories.

```rust
pub struct WorkspaceTrust {
    trusted_paths: HashSet<PathBuf>,  // persisted in config
}
```

First access to untrusted workspace → prompt user to trust (interactive channels only). Untrusted workspace restricts to a built-in read-only allowlist — **no plugin tools, no skill tools, no MCP tools, no bash**:

- **Allowed (built-in read-only only):** `file.read`, `file.list`, `memory.search`, `grep`, `glob` (these are illustrative — canonical tool IDs to be derived from `ToolRegistry::export_snapshot()` at implementation time; this is a new API to add in Phase A returning tool IDs in deterministic sorted order; the runtime registry is the single source of truth)
- **Blocked:** all WASM/Javy skills, all MCP server tools, all native plugin tools (`digest_*`, `netprobe_*`, `browser_*`), `bash.exec`, `file.write`, `file.edit`
- Plugin tools like `digest_summarize` are blocked even though they appear "read-only" — they make network calls or invoke external processes (PDF extraction), which violates the untrusted execution boundary

**Non-interactive fallback (cron, webhooks, channel adapters, headless):**
- Default policy: `untrusted_default: deny` — treat as untrusted, same built-in read-only allowlist as above
- Configurable per-workspace in config: `workspace_trust.trusted_paths: ["/home/user/projects"]` for paths that should be trusted without interactive prompt
- Audit log entry emitted when trust is auto-denied in non-interactive context

Trust persisted per workspace path in user settings.

**Files:** `crates/core/src/config.rs`, `crates/gateway/src/server.rs`

---

### 4.12 Permission Modes

**Purpose:** Different trust levels for different use cases.

| Mode | Behavior | Use Case |
|------|----------|----------|
| `default` | Prompt for sensitive/critical tools | Normal interactive use |
| `plan` | All tools disabled, agent thinks only | Planning, safe exploration |
| `readonly` | Only read-only tools | Research, browsing |
| `bypass` | All tools allowed except immutable deny-list | Trusted automation, cron jobs |

`PermissionMode` checked in `ToolRegistry::dispatch()`. Session-level override.

**Immutable deny-list (enforced even in bypass mode):**
These operations are never auto-allowed regardless of permission mode:
- `rm -rf /` and path-destructive shell patterns (regex match)
- Credential file writes (`.ssh/`, `.gnupg/`, `.env`)
- Fork bombs, raw disk writes (`dd if=`, `mkfs`)
- Network operations to private IP ranges when `block_private_ranges` is enabled

The deny-list is compiled into the binary, not configurable — preventing accidental override. The core deny-list covers universally dangerous operations only. Domain-specific policies (e.g., git force-push to protected branches) belong in their respective plugins (e.g., CodeOps plugin).

**Enforcement points by tool family:**

| Tool family | Deny-list check | Enforcement location |
|-------------|----------------|---------------------|
| `bash.exec` | Regex match on command string (rm -rf, fork bomb, mkfs, dd if=, DROP TABLE) | `risk_classifier.rs` |
| `file.write` / `file.edit` | Path match against credential patterns (`.ssh/`, `.gnupg/`, `.env`) | `risk_classifier.rs` + `local_tool_policy.rs` / edge `LocalPolicy` (defense-in-depth: file policy layers also enforce credential-path deny independently of the classifier) |
| `netprobe_fetch` / any HTTP | Destination IP checked against private ranges when `block_private_ranges` enabled | `firewall.rs` (existing) |

**Implementation phasing:**
- **Phase A:** Deny-list enforced as a hardcoded check in `risk_classifier.rs` covering bash and file-write tool families. This is the safety-critical path — it works without the full permission mode system. Network deny-list reuses existing `firewall.rs`.
- **Phase B:** `PermissionMode` enum added to `policy.rs`, integrating the deny-list check into the formal permission decision flow. The A-phase runtime check remains as a defense-in-depth backstop.

**Files:** `crates/agent/src/risk_classifier.rs` (Phase A), `crates/core/src/policy.rs` (Phase B), `crates/agent/src/runtime.rs`

---

### 4.13 Hook System (27 Events)

Expand from 9 to 27 lifecycle hook events with async support:

| Category | Events | Can Block? |
|----------|--------|------------|
| Session | SessionStart, SessionEnd, Setup | No |
| Tool | PreToolUse, PostToolUse, PostToolUseFailure | PreToolUse: Yes |
| Permission | PermissionRequest, PermissionDenied | PermissionRequest: Yes |
| Agent | SubagentStart, SubagentStop | No |
| Config | ConfigChange, CwdChanged, FileChanged, InstructionsLoaded | No |
| Task | TaskCreated, TaskCompleted | No |
| User | UserPromptSubmit, Elicitation, ElicitationResult | UserPromptSubmit: Yes |
| Compact | PreCompact, PostCompact | No |
| Lifecycle | Stop | Yes |
| Registry | ToolRegistered, ToolUnregistered | No |
| Memory | MemoryStored, MemoryDeleted | No |
| Channel | ChannelMessageReceived | No |

Execution models: Shell command, HTTP POST webhook, in-process callback, agent invocation.

Async contract: configurable timeout (default 10s), fail-open on timeout.

**Files:** `crates/core/src/hooks.rs`, `crates/gateway/src/plugin_api.rs`

---

### 4.14 Memory Type Taxonomy

4 memory types with enforced classification:

| Type | Purpose | Example |
|------|---------|---------|
| `user` | Role, preferences, expertise | "Senior Rust dev, prefers concise answers" |
| `feedback` | Corrections and validated approaches | "Don't add docstrings unless asked" |
| `project` | Ongoing work, goals, decisions | "Sprint 7 done, working on plugins" |
| `reference` | Pointers to external systems | "Bug tracker in Linear project INGEST" |

- `memory_type` column added to `memory_entries` table
- Type-aware search: "find all project memories", "find feedback about testing"
- Drift validation: verify memory against current state before acting on it

**Files:** `crates/core/src/types.rs`, `crates/storage/` (migration), `crates/memory/src/`

---

### 4.15 Dream Memory Consolidation

**Purpose:** Asynchronous distillation of daily interactions into high-quality long-term memories.

- Cron job runs during configurable quiet hours
- Dream agent reads recent session transcripts
- Extracts key facts, decisions, feedback → writes typed memories
- Short-term logs → long-term structured memories (async, not real-time)

```yaml
memory:
  dream:
    enabled: true
    schedule: "0 3 * * *"     # 3 AM daily
    lookback_hours: 24
```

**Files:** `crates/gateway/src/handlers/cron.rs`, `crates/agent/` (dream agent prompt)

---

### 4.16 Deferred Tool Loading (ToolSearch)

**Purpose:** Keep system prompt small as tool count grows (20+ tools → significant token cost).

- Non-core tools marked `defer_loading: true` in registry
- Deferred tools excluded from system prompt
- `tool_search` meta-tool: agent calls with intent → matching tool schemas returned
- Loaded schemas injected into next turn's context

**Files:** `crates/agent/src/tool_registry.rs`, new `crates/agent/src/tool_search.rs`

---

### 4.17 Large Result Management

**Purpose:** Prevent context window blowup from oversized tool outputs.

When tool result exceeds `max_result_size_chars`:
1. Write full result to `~/.encmind/tool_results/{id}.txt`
2. Return truncated preview + file path reference to LLM
3. Agent can later read full result via `digest_file` if needed (the tool results directory is automatically added to `digest.file_root` allowlist at startup; `digest_file` is a plugin tool, so this retrieval path is only available in trusted workspaces — in untrusted workspaces the truncated preview is the final output)

**Retention & safety controls:**
- **TTL:** Results auto-deleted after configurable TTL (default: 24 hours). Cleanup runs on startup and periodically.
- **Quota:** Maximum total disk usage for tool results (default: 500 MiB). Oldest files evicted when quota exceeded.
- **Redaction:** Tool results from tools with `CapabilityRiskLevel::Critical` (per existing `policy.rs` classification) are never persisted to disk — only the truncated preview is kept. This reuses the existing risk-level model rather than adding a new field.
- **Encryption-at-rest:** Deferred to future phase. Files are stored in the user's home directory with standard filesystem permissions.

**Files:** `crates/agent/src/runtime.rs`, new `crates/agent/src/result_store.rs`

---

### 4.18 Startup Profiling

**Purpose:** Faster cold start, operator visibility into slow phases.

- Startup profiler with `checkpoint(name)` and `report()`
- Parallel initialization: config load, DB warm, credential fetch as concurrent tasks
- `encmind diagnose startup` CLI command

**Files:** `crates/gateway/src/server.rs`, `crates/cli/`

---

### 4.19 Agent Behavioral Governance

**Purpose:** Prevent common LLM failure modes through explicit behavioral constraints, not model self-discipline.

LLMs have predictable bad habits when used as coding agents: over-engineering, adding unrequested features, skipping code reads before edits, faking test results, over-abstracting, lazy delegation to sub-agents. These aren't intelligence failures — they're behavioral defaults that must be overridden by system-level rules.

**Two layers:**

**Layer 1 — Prompt-level behavioral constraints (in system prompt):**

Injected into every agent's system prompt as non-negotiable rules:
- Read existing code before suggesting modifications
- Do not add features, refactors, or "improvements" beyond what was asked
- Do not add error handling, fallbacks, or validation for scenarios that can't happen
- Do not create abstractions for one-time operations
- Do not give time estimates
- Report results honestly — never claim tests passed without running them
- When an approach fails, diagnose root cause before switching strategies
- Delete confirmed-unused code cleanly, no compatibility shims

**Layer 2 — Tool usage grammar (also in system prompt):**

Enforce correct tool selection to prevent fragile shell workarounds:
- Read files → use `file.read`, not `bash cat/head/tail`
- Edit files → use `file.edit`, not `bash sed/awk`
- Search files → use `grep`/`glob` tools, not `bash find/grep`
- Create files → use `file.write`, not `bash echo >`
- Reserve `bash.exec` for operations that genuinely need a shell

This eliminates a class of failures where the model uses `sed` with a broken regex instead of the structured edit tool.

**Implementation:**
- `BehavioralConstraints` prompt section in `build_system_message()` — static, cacheable
- `ToolUsageGrammar` prompt section — static, generated from tool registry metadata
- Per-agent override: Verification agent gets adversarial constraints, Explore agent gets read-only constraints

**Files:** `crates/agent/src/context.rs` (prompt sections), `crates/core/src/config.rs` (configurable overrides)

---

### 4.20 Tool Execution Governance Pipeline

**Purpose:** Every tool call passes through a complete governance chain, not just "find handler → execute."

The current flow is: dispatch → permission check → execute → return. The target flow adds input validation, risk classification, and structured post-processing:

```
Phase A (runtime-internal):
  1. Resolve tool definition from registry
  2. Input validation (schema check — tool_use.input must match declared schema)
  3. Speculative risk classification (deny-list + destructive pattern match)
  4. Run existing BeforeToolCall hook (9 current HookPoints)
  5. Permission check (current CapabilityRiskLevel policy)
  6. Execute tool.call()
  7. Record analytics (duration, success/failure)
  8. Run existing AfterToolCall hook
  9. On failure: log + internal error context (no formal failure hook yet)
  10. Return structured result

Phase B (full hook expansion):
  Steps 4, 8, 9 upgraded to formal HookPoints with async contract:
  4. Run PreToolUse hooks (can: modify input, allow/deny, inject context, block)
  5. Permission decision (mode + policy + hook result)
  8. Run PostToolUse hooks (can: append context, trigger side effects, modify output)
  9. Run PostToolUseFailure hooks (can: provide recovery hints)
```

**Phase A ships the pipeline structure using the existing 9 HookPoints.** Steps 1-3 and 6-7 are new runtime code. Steps 4/8 delegate to the current hook system. Step 9 is internal logging only.

**Phase B upgrades steps 4/8/9 to the expanded 27-event hook system** with async contract, timeout, and the full PreToolUse/PostToolUse/PostToolUseFailure semantics.

**Key governance principle — hook power boundaries:**
- PreToolUse hook says `allow` → still subject to permission mode rules (if mode is `default` and tool is `Critical`, user is still prompted)
- PreToolUse hook says `deny` → takes effect immediately, no override
- Hooks can modify input and inject context, but cannot escalate permissions beyond what the permission mode allows
- This ensures hooks are powerful (runtime policy, custom gates) but controlled (can't bypass security model)

**Speculative risk classifier (for bash commands):**
```rust
pub fn classify_bash_risk(command: &str) -> RiskLevel {
    // Pattern-match for universally dangerous operations before execution
    // rm -rf, fork bomb, mkfs, dd if=, DROP TABLE, credential path writes
    // Returns Low/Sensitive/Critical/Denied
}
```

This runs BEFORE hooks and permission checks — it's a pre-filter that flags obviously dangerous commands for extra scrutiny even in `bypass` mode (feeds into the immutable deny-list from 4.12).

**Structured permission decisions:**

Denials carry a typed `PermissionDecision { source, rule_id, reason, input_fingerprint }` record rather than a free-form string. The `source` is one of `risk_classifier | workspace_trust | firewall | approval | hook | rate_limit | schema`, and `input_fingerprint` is a short SHA-256 prefix for log correlation. The record flows through the `AfterToolCall` hook payload (alongside a `ToolOutcome` discriminator: `success | failure | denied`) and into audit events, giving operators a single typed object to answer "why did this get denied?" without string parsing. Plugins can branch on `outcome` in a single hook point instead of needing a separate failure hook.

For backward compatibility, `rule_id` for every mapped denial is pinned to the legacy flat code (`immutable_deny_list`, `workspace_untrusted`, `egress_firewall`, `policy_denied`, `approval_denied`). A deprecated flat `deny_reason` field is emitted alongside the structured record on hook payloads and in the `chat.send` response — it is derived from `rule_id` (falling back to `source` only if no rule_id is set), so existing consumers of the pre-structured contract continue to see their original values verbatim during the transition window.

**Schema validation is intentionally fail-open.** LLMs routinely emit near-miss inputs (stringified numbers, extra fields). A hard schema reject would turn transient model sloppiness into tool errors; individual tool handlers remain the authoritative validators. An **optional per-tool strict mode** for high-risk tools is a future enhancement, tracked with B.8 — the global default stays fail-open.

**Files:** `crates/agent/src/runtime.rs` (pipeline), `crates/agent/src/risk_classifier.rs`, `crates/core/src/permission.rs` (`PermissionDecision`, `DecisionSource`), `crates/core/src/hooks.rs` (`ToolOutcome`, power boundary rules)

---

### 4.21 Built-in Agent Roles with Permission Isolation

**Purpose:** Specialized agent roles with hard capability constraints, not just different prompts.

Generic coordinator/worker is not enough. Different phases of work need different permission profiles to prevent cross-contamination:

| Role | Can Read | Can Write | Can Execute | Use Case |
|------|----------|-----------|-------------|----------|
| **Explore** | file.read, grep, glob, git log/diff/status | No | No | Codebase research, architecture understanding |
| **Plan** | file.read, grep, glob | No | No | Design, implementation planning, file identification |
| **Implement** | All read tools | file.write, file.edit | bash, git commit | Code changes |
| **Verify** | All read tools | No (except test files) | bash (test/build/lint only) | Adversarial validation |

**Why Explore and Plan are read-only:**
If the exploration phase accidentally modifies a file, the implementation phase builds on corrupted state. Hard read-only constraints eliminate this class of bugs entirely.

**Verification Agent — adversarial by design:**

The Verify role is the most important specialization. Its system prompt is explicitly adversarial:
- Direction is "try to break it", not "confirm it looks OK"
- Must run actual commands (build, test, lint, type-check) and include real output
- Must perform adversarial probes: edge cases, boundary conditions, missing error handling
- Must give a verdict: PASS, FAIL, or PARTIAL with specific evidence
- Two failure modes to guard against:
  1. **Verification avoidance:** reading code but not running checks
  2. **80% trap:** UI looks fine and tests pass, so ignoring remaining issues

The implementation-verification separation prevents the "I wrote it so it must be correct" bias that occurs when the same agent both implements and validates.

**Implementation:**
```rust
pub enum AgentRole {
    Explore,    // read-only tools only
    Plan,       // read-only tools only, outputs structured plan
    Implement,  // full tool access
    Verify,     // read + test/build/lint execution only
    General,    // coordinator or interactive — full access
}

impl AgentRole {
    pub fn allowed_tool_filter(&self) -> Box<dyn Fn(&str) -> bool> {
        // Returns filter that tool registry uses to gate dispatch
    }
}
```

- Role assigned at agent spawn time, enforced by tool registry filter
- Coordinator selects role based on task phase
- Role cannot be changed after spawn (no privilege escalation mid-run)

**Files:** `crates/agent/src/subagent.rs` (role enum + filter), `crates/agent/src/runtime.rs` (enforce filter), `crates/agent/src/context.rs` (role-specific prompt sections)

---

### 4.22 Coordinator Prompt Quality Requirements (Anti-Lazy-Delegation)

**Purpose:** Prevent coordinators from delegating vague tasks that sub-agents can't execute well.

The most common multi-agent failure: coordinator sends "investigate the bug and fix it" to a worker. Worker has no context, misinterprets the task, returns garbage. Coordinator doesn't know the result is wrong.

**Enforced via coordinator system prompt rules:**

1. **Fresh agents have no context.** Write prompts as if briefing a new team member:
   - State the goal and why it matters
   - List what you've already ruled out
   - Provide specific file paths and line numbers
   - If you want a short answer, say so explicitly

2. **Don't outsource understanding.** Bad: "Based on your findings, fix the bug." Good: "In `crates/agent/src/runtime.rs:245`, the `process_tool_result` function doesn't handle the case where `tool_use.input` is a string instead of an object. Add a normalization step before line 250."

3. **Coordinator owns synthesis.** Workers return raw findings. Coordinator must synthesize across workers before acting. Never forward one worker's output directly to another without review.

4. **Specify output format.** Tell the worker exactly what to return: "Return a list of file paths with the function names that need changing" vs "Look into it."

**Implementation:** These rules are part of the coordinator role's prompt section (4.19 behavioral governance). No runtime enforcement needed — prompt-level constraint.

**Files:** `crates/agent/src/context.rs` (coordinator prompt section)

---

### 4.23 Structured Compaction Prompt (Refine 4.3)

**Purpose:** The auto-compact strategy needs a specific prompt template to produce useful summaries — "LLM summarizes conversation" is not enough.

**Three operating modes:**

| Mode | When | Summarizes |
|------|------|------------|
| Full compaction | Entire conversation exceeds budget | All messages |
| Partial (recent) | Recent messages are large | Only recent messages; older retained |
| Partial (older) | Older messages are stale | Only older messages; recent retained |

**Full compaction template (9 required sections — used only for full mode):**

```
1. Primary Request and Intent — What the user is trying to accomplish
2. Key Technical Concepts — Domain terms, patterns, constraints established
3. Files and Code Sections — Specific files read/modified with key line ranges
4. Errors and Fixes — What went wrong and how it was resolved
5. Problem Solving — Approach taken, alternatives considered, dead ends
6. All User Messages (condensed) — Key user messages preserving intent
7. Pending Tasks — Work not yet completed
8. Current Work — What was actively being worked on
9. Optional Next Step — What should happen next
```

**Partial compaction template (lightweight — used for recent/older modes):**

```
Summarize only the [recent/older] messages below. The [older/recent] context
is already retained and should NOT be re-summarized. Focus on:
- What was done (files changed, tools called, decisions made)
- What remains open
Keep under 500 tokens.
```

Partial mode uses the lightweight template to avoid spending a full LLM call on re-summarizing what's already retained. This keeps compaction cost proportional to the range being compacted, not the full conversation.

**Minimum required fields (both modes — never drop these):**

Even the lightweight partial template MUST preserve these fields if they exist in the compacted range. Dropping them causes "compaction amnesia" where the agent forgets constraints it was operating under:
- Open/pending tasks (from task system or user instructions)
- Unresolved errors (failures not yet fixed)
- Active constraints (user-stated requirements, "don't touch X", architectural decisions)
- Pending approvals (actions waiting for user confirmation)

The partial template includes: "You MUST preserve any open tasks, unresolved errors, active constraints, and pending approvals from the summarized range — even if they take extra tokens."

**Analysis scratchpad pattern (both modes):**
- LLM writes reasoning in `<analysis>` tags before the `<summary>` tags
- `<analysis>` content is stripped before the summary enters context
- This improves summary quality (chain-of-thought) without wasting context tokens

**Implementation:** `CompactionController` selects template based on mode. Full compaction uses the 9-section template; partial uses the lightweight template.

**Files:** `crates/agent/src/compaction.rs`

---

### 4.24 Proactive/Autonomous Agent Mode

**Purpose:** Always-on agent that actively monitors, investigates, and acts between user interactions — not just responding to messages but continuously working.

EncMind already has cron for scheduled tasks. Proactive mode is different: it's a persistent agent loop with intelligent pacing, focus awareness, and cache-efficient sleep.

**Design:**

```yaml
agents:
  proactive:
    enabled: false             # default OFF — must be explicitly enabled
    idle_sleep_secs: 60        # sleep when nothing to do
    active_sleep_secs: 5       # sleep between active steps
    cache_ttl_secs: 300        # prompt cache expires after 5 min inactivity
    max_duration_secs: 3600    # wall-clock hard stop (1 hour)
    max_tokens_per_session: 100000
    max_turns_per_session: 200
    channel_auto_reply: false  # do not auto-reply to channel messages
```

**Tick-based keep-alive:**
- Agent receives periodic `<tick>` messages with current local time
- On tick: evaluate if there's useful work (pending tasks, unread messages, stale checks)
- If nothing useful: call Sleep immediately (no idle narration — it wastes tokens)
- Multiple ticks may batch — process only the latest

**Cache-aware pacing:**
- Prompt cache expires after `cache_ttl_secs` of inactivity
- Sleep duration must balance "don't waste API calls" vs "don't lose cache"
- Active work: short sleep (5s). Idle monitoring: longer sleep (60s) but under cache TTL

**Channel focus awareness:**
- If the user is actively chatting (recent message in channel): prioritize responding, keep feedback loop tight
- If the user is away (no recent activity): lean into autonomous action — make decisions, commit, push
- Only pause for genuinely irreversible or high-risk actions

**Anti-narration rule (critical):**
- Never output "still waiting", "nothing to do", "checking for work"
- If there's nothing to do, Sleep silently
- Text output only for: decisions needing input, milestone updates, errors/blockers

**Hard safety gates (mandatory):**
- **Default OFF** — must be explicitly enabled per session or in config
- **Per-session token cap:** `proactive.max_tokens_per_session` (default: 100K). Session terminates when reached.
- **Per-session turn cap:** `proactive.max_turns_per_session` (default: 200). Prevents infinite loops.
- **Wall-clock cap:** `proactive.max_duration_secs` (default: 3600 = 1 hour). Hard stop regardless of progress.
- **Provider backoff gate:** if the LLM provider returns rate-limit (429) or consecutive 5xx errors, proactive mode pauses for the backoff duration. 3 consecutive provider errors → auto-suspend for the session.
- **Operator kill-switch:** `proactive.enabled: false` in config or `proactive.stop` RPC method immediately terminates all active proactive sessions. No graceful drain — hard stop.
- **Idle detection and escalation:**
  - A tick is **idle** when: no new user messages since last tick AND no pending tasks/tool calls AND no unprocessed notifications. Tool failures do NOT count as idle (they may need investigation).
  - 3 consecutive idle ticks → force Sleep to `idle_sleep_secs` minimum
  - 10 consecutive idle ticks → auto-suspend proactive mode for the session
  - Any user message or new task resets the idle counter
- **Channel auto-reply disabled by default:** proactive mode does NOT auto-reply to inbound channel messages (Telegram, Slack) unless `proactive.channel_auto_reply: true` is explicitly set. Prevents unexpected bot behavior in group chats.
- **Cost telemetry:** every proactive session logs cumulative tokens spent, turns taken, and useful-action ratio. Operator can set `proactive.cost_alert_tokens` threshold for notifications.

**Relationship to cron:**
- Cron = scheduled, deterministic, fire-and-forget jobs
- Proactive = continuous, adaptive, context-aware agent loop
- Both can coexist. Proactive mode can incorporate cron results as inputs

**Files:** new `crates/agent/src/proactive.rs`, `crates/gateway/src/handlers/agents.rs`

---

### 4.25 Permission Explainer Side-Query

**Purpose:** When the user is prompted for tool permission (in `ask` mode), concurrently explain what the tool will do and why, so the user can make an informed decision.

**Design:**
- Fires as a parallel side-query while the permission prompt is shown
- Uses a smaller/cheaper model (not the main agent model)
- Produces structured JSON:

```json
{
  "explanation": "What this command does (1-2 sentences)",
  "reasoning": "Why the agent is running this (starts with 'I need to...')",
  "risk": "What could go wrong (under 15 words)",
  "riskLevel": "LOW | MEDIUM | HIGH"
}
```

- Displayed alongside the permission prompt in web UI / edge CLI
- Configurable: `security.permission_explainer: true`

**Risk levels:**
- LOW: read-only operations (ls, cat, git status)
- MEDIUM: recoverable changes (file edits, package install)
- HIGH: destructive/irreversible (rm -rf, DROP TABLE, credential writes)

**Files:** `crates/gateway/src/handlers/chat.rs`, new `crates/gateway/src/permission_explainer.rs`

---

### 4.26 LLM-Powered Memory Selection

**Purpose:** Vector search returns semantically similar memories, but misses contextual relevance. Add an LLM filtering layer that selects the most useful memories for the current query.

**Current flow:** query → embedding → vector search → top-K results → inject into context

**New flow (two-stage):**
1. **Recall stage:** vector search + FTS keyword match → broad candidate set (top 30-100). Cast a wide net to avoid missing relevant memories.
2. **Rerank stage:** send candidate manifest (title + description + 200-char leading snippet per entry) to a cheap/fast model → select up to 5 most relevant.

**Design:**
- Stage 1 uses existing hybrid search (vector + FTS5 RRF). Broadened K (30-100 instead of current top-10) to reduce false negatives.
- Stage 2 sends per-candidate: title + description + leading snippet (first 200 chars of content). Full content is NOT sent — keeps rerank cost low while giving the model enough signal to judge relevance.
- **Diversity constraint (MMR):** rerank prompt instructs the model to maximize marginal relevance — avoid selecting 3 memories that all say the same thing. Prefer coverage across different topics/types over clustering on the highest-scoring topic.
- Selection criteria: clearly useful > diverse coverage > skip redundant API docs > keep gotchas/warnings
- Empty list is valid (if no memories are relevant)
- Fallback: if rerank model is unavailable or times out, fall back to stage-1 top-5 (current behavior)

```rust
pub async fn select_relevant_memories(
    query: &str,
    candidates: &[MemoryEntry],
    llm: &dyn LlmBackend,
) -> Result<Vec<MemoryEntry>, AppError> {
    // Send compact manifest to cheap model
    // Return filtered list
}
```

**Files:** `crates/memory/src/`, `crates/agent/src/context.rs`

---

### 4.27 Away Summary (Session Recap)

**Purpose:** When a user returns to a channel/session after being away, generate a brief recap so they can re-orient without scrolling.

**Design:**
- Trigger: user sends first message in a session that has been idle for >N minutes (configurable, default 30)
- Uses last 30 messages (not full history) to avoid prompt-too-long
- Cheap/fast model, no thinking, no tool calls
- Output: exactly 1-3 sentences. Start with the high-level task, end with the concrete next step. Skip status reports and commit recaps.

```
The user stepped away and is coming back. Write exactly 1-3 short sentences.
Start by stating the high-level task — what they are building or debugging,
not implementation details. Next: the concrete next step.
Skip status reports and commit recaps.
```

**Files:** `crates/gateway/src/handlers/chat.rs`, `crates/agent/src/context.rs`

---

### 4.28 Prompt Suggestion Service

**Purpose:** After each assistant turn, predict 1-3 short follow-up prompts the user might naturally say next. Displayed as clickable options in web UI.

**Design:**
- Fires asynchronously after every assistant turn (doesn't block response)
- Uses cheap/fast model
- Each suggestion: 2-8 words, matches user's communication style
- Prioritize actionable requests over questions
- Don't suggest things the assistant just completed
- If the task seems done, suggest verification or next logical steps
- Deduplicates against recently executed commands

```json
["Run the tests", "Show me the diff", "Deploy to staging"]
```

**Files:** `crates/gateway/src/handlers/chat.rs`, web-ui integration

---

### 4.29 Background Worker Progress Summaries

**Purpose:** Coordinator needs to monitor background workers without reading their full output. Workers emit periodic present-tense single-sentence progress descriptions.

**Design:**
- Workers generate progress summary every N seconds (configurable, default 10)
- Uses cheap model, present-tense, specific:
  - Good: "Reading the authentication middleware in auth/middleware.rs"
  - Bad: "Working on the task" (too vague)
- Coordinator receives summaries as `<agent-progress>` injections
- Displayed in web UI worker pane

**Files:** `crates/agent/src/subagent.rs`, `crates/gateway/src/handlers/agents.rs`

---

### 4.30 Agent Creation Architect (Self-Extensible Agents)

**Purpose:** Let users create new specialized agent roles by describing what they want, without writing system prompts manually.

**Design:**
- User says: "Create an agent that reviews database migrations for safety"
- Architect meta-agent generates:
  - `identifier`: "migration-reviewer"
  - `whenToUse`: "Use this agent when reviewing database migration files for safety issues..."
  - `systemPrompt`: Complete operational prompt with domain expertise, methodology, edge cases, quality checks
- Generated agent is saved to config and available for spawning
- Considers CLAUDE.md / project context when generating prompts

**Files:** `crates/agent/src/context.rs` (architect prompt), `crates/core/src/config.rs` (agent storage)

---

### 4.31 Session Title Auto-Generation

**Purpose:** Auto-generate concise titles for sessions, improving session management UX across web UI and CLI.

**Design:**
- Fires after first meaningful exchange (not on greeting)
- Uses cheap/fast model: "Generate a 3-7 word sentence-case title"
- Examples: "Fix login button on mobile", "Add OAuth authentication"
- Stored in session metadata, displayed in session list

**Files:** `crates/gateway/src/handlers/chat.rs`, `crates/storage/` (session title column)

---

### 4.32 Session Search (Cross-Session Retrieval)

**Purpose:** `memory.search` retrieves stored knowledge memories. Session search is different — it finds past conversation sessions by topic, enabling "what did we discuss about X last week?"

This is distinct from memory search:
- **memory.search:** returns distilled knowledge entries (facts, decisions, feedback)
- **session.search:** returns past session transcripts/summaries by semantic match

**Design:**
- Search across session metadata: title, tags, branch, summary, transcript excerpts
- Priority: exact tag match > partial tag match > title match > branch match > summary > semantic similarity
- Inclusive: return more results rather than too few (user can narrow down)
- Uses cheap/fast model for ranking
- Returns: session_id, title, date, relevance snippet

**Files:** `crates/gateway/src/handlers/`, `crates/storage/` (session search index)

---

### 4.33 Browser Automation Safety Rules

**Purpose:** EncMind already has a browser pool (`encmind-browser` crate). These prompt-level rules prevent common browser automation failures that waste agent turns.

**Rules to inject into agent prompt when browser tools are active:**

1. **Dialog avoidance:** Do not trigger JavaScript alert/confirm/prompt dialogs — they block the page and require manual dismissal. If you need to test form validation, check the DOM state instead.
2. **Stateful interaction via `browser_act`:** For multi-step UI flows (click → fill → submit), use `browser_act` within the same chat session (same runtime session_id) to preserve page state across actions. `browser_navigate` and `browser_get_text` are stateless one-shot tools that each acquire a fresh page — do not use them for sequential interactions expecting shared DOM state.
3. **Anti-loop detection:** If the same navigation/click sequence produces the same error 3 times, stop and report the failure instead of retrying.
4. **Error recovery:** If a page fails to load or a selector is not found, wait once (2s), retry once. If still failing, take a screenshot for diagnostics and report.
5. **Frame recording:** When performing multi-step UI interactions, capture screenshots before AND after each action for verification.

**Prompt-level:** These rules are added as a conditional prompt section when `browser.enabled: true` — part of the behavioral governance system (4.19).

**Runtime guardrails (in addition to prompt rules):**

| Guardrail | Enforcement | Location |
|-----------|-------------|----------|
| Max retries per action | 3 attempts, then abort with error | `BrowserPool` tool handler |
| Loop detection | Track last 5 (url, selector, action) tuples; if 3 identical → abort | `BrowserPool` tool handler |
| Dialog recovery | If CDP detects a JS dialog event, auto-dismiss and log warning | `BrowserPool` event listener |
| Action timeout | Per-action timeout (default 10s); page load timeout (default 30s) | `BrowserPool` config |
| Metrics | `browser.loop_abort_count`, `browser.dialog_dismissed_count`, `browser.timeout_count` | Telemetry/audit log |

The prompt rules tell the agent what NOT to do. The runtime guardrails catch it when the agent does it anyway.

**Files:** `crates/agent/src/context.rs` (prompt section), `crates/browser/src/` (runtime guardrails)

---

## 5. Implementation Plan

### Phase A — Runtime Safety & Correctness (P0)

Foundation. Nothing else ships until these are stable. Focus: prevent corruption, validate payloads, govern tool execution, stream events, gate untrusted workspaces.

| # | Feature | Effort | Acceptance Criteria |
|---|---------|--------|---------------------|
| A.1 | Per-session query guard + FIFO queue | 1-2 days | Concurrent chat.send serialized per session |
| A.2 | Message normalization pipeline | 1-2 days | No `invalid_request_error` 400s caused by tool payload schema mismatch (other 400 classes out of scope) |
| A.3 | Tool execution governance pipeline | 2-3 days | Full chain: validate → risk classify → pre-hook → permission → execute → post-hook; denials carry typed `PermissionDecision { source, rule_id, reason, input_fingerprint }`; `AfterToolCall` payload includes `ToolOutcome { Success / Failure / Denied }` discriminator; formal failure hook still deferred to B.5 |
| A.4 | Streaming event pipeline (ChatEvent) | 5-7 days | delta/tool_start/progress/complete/done events end-to-end |
| A.5 | Streaming tool executor (parallel safe) | 5-7 days | Read-only tools run in parallel, destructive serialize |
| A.6 | Workspace trust + immutable deny-list | 2-3 days | Untrusted dirs cannot load plugins/skills/MCP; deny-list enforced even in bypass mode |
| A.7 | Agent behavioral governance (prompt sections) | 1-2 days | Behavioral constraints + tool usage grammar + browser safety rules in system prompt |
| A.8 | Local server mode (enhance existing) | 2-3 days | LocalToolHandler wired into workspace trust gate, operator-configurable denied_paths layered on defaults, BashMode::Allowlist patterns enforced at dispatch, symlink containment verified via canonicalization |
| A.9 | Backpressure & graceful shutdown | 2-3 days | Bounded WS buffer, clean drain on SIGTERM |
| A.10 | Withhold-and-recover errors | 2-3 days | Recoverable errors retried before surfacing to user |
| A.11 | Error recovery circuit breaker | 2-3 days | Consecutive failures stop retrying, degrade gracefully |
| A.12 | Browser runtime guardrails | 1-2 days | Max retries, loop detection, dialog auto-dismiss, action timeout, metrics |

**Phase A done when:** Session-level query serialization enforced, message normalization catches malformed payloads, tool governance pipeline operational, streaming event protocol stable, untrusted workspaces restricted, browser runtime guardrails active (loop detection, dialog dismiss, retry cap, action timeout, metrics).

**Estimated total: 4-6 weeks** (conservative: 6-8 weeks if streaming executor proves more complex than estimated — highest-risk item)

---

### Phase B — Cost & Performance (P1)

Build on Phase A's stable execution model. Focus: token cost reduction, context longevity, large result handling.

| # | Feature | Effort | Acceptance Criteria |
|---|---------|--------|---------------------|
| B.1 | Prompt compiler + cache boundary | 2-3 days | Static sections cached, cache-break diagnostics visible |
| B.2 | Prompt cache engineering (sort, hash, externalize) | 1 day | Deterministic tool order, hash paths, metadata externalized |
| B.3 | Multi-strategy compaction + structured prompt | 3-5 days | 4 strategies + 2 controls + 9-section summary template + analysis-scratchpad pattern |
| B.4 | Large result persist-to-disk + preview | 1 day | Oversized results truncated with disk pointer, TTL + quota |
| B.5 | Hook system: 27 events + async contract | 3-4 days | All hook events firing, async hooks with timeout |
| B.6 | Permission modes (default/plan/readonly/bypass) | 2-3 days | Mode enforced per session |
| B.7 | Memory type taxonomy | 1-2 days | 4 types enforced, type-aware search working |
| B.8 | Permission decision tracing (finish) | 1 day | Base `PermissionDecision` type shipped in A.3; B.8 adds: per-tool strict schema mode for high-risk tools, decision rendering in web UI timeline, structured audit filter by source/rule_id |
| B.9 | Startup profiling + parallel prefetch | 1-2 days | Cold start profiled, parallel init working |
| B.10 | ToolUseContext dependency injection | 2-3 days | All tools receive context, mocked in tests |
| B.11 | Permission explainer side-query | 1-2 days | Concurrent risk explanation shown alongside permission prompt |
| B.12 | LLM-powered memory selection | 2-3 days | 2-stage recall+rerank with MMR diversity; stage-1 fallback on rerank failure |
| B.13 | Session title auto-generation | 0.5 day | 3-7 word title generated after first meaningful exchange |

**Phase B done when:** Cache-break diagnostics visible, compaction avoids failure loops, large results governed with TTL/quota, hook contract stable.

**Estimated total: 4-5 weeks**

---

### Phase C — Multi-Agent Orchestration (P2)

Needs Phase A streaming executor and governance pipeline. Phase B hooks enhance but do not block. Focus: role-specialized agents, task management, tool scaling.

| # | Feature | Effort | Acceptance Criteria |
|---|---------|--------|---------------------|
| C.1 | Built-in agent roles (Explore/Plan/Implement/Verify) | 3-4 days | Role-based tool filter enforced, Verify agent adversarial |
| C.2 | Coordinator mode + async notifications + worker progress | 3-4 days | Coordinator spawns workers, receives notifications + progress summaries |
| C.3 | Planning tasks (persistent, owned) | 2-3 days | 5 task tools working, ownership claims atomic |
| C.4 | Runtime execution tasks (ephemeral, polling, eviction) | 3-4 days | Background execution with delta streaming, status events via WS, grace-period eviction |
| C.5 | Fork subagents + prompt cache sharing | 4-5 days | Child inherits parent messages, cache hit on prefix |
| C.6 | Deferred tool loading (ToolSearch) | 2-3 days | Non-core tools loaded on demand |
| C.7 | Stop hooks + continuation prevention | 1-2 days | Hooks can veto continuation (budget, policy) |

**Phase C done when:** Async workers and task notifications reliable under parallel load. Verify agent catches regressions that Implement agent misses. ToolSearch keeps prompt size stable as tool count grows.

**Estimated total: 4-5 weeks**

---

### Phase D — Long-Term Capabilities (P3)

Memory evolution and optional autonomy features. Independent of P0-P2 except Dream consolidation (needs memory type taxonomy from B.7).

| # | Feature | Effort | Acceptance Criteria |
|---|---------|--------|---------------------|
| D.1 | Dream memory consolidation | 2-3 days | Nightly distillation produces typed memories, retrieval quality improves |
| D.2 | Auto-mode permission classifier (feature-flagged) | 3-4 days | Cheaper model side-query for bash safety, degradation tracking; default OFF |
| D.3 | Agent-specific MCP servers | 1 day | Per-agent MCP config, shared clients memoized |
| D.4 | Settings precedence (user→project→local→flags→policy) | 1 day | 5-layer settings, highest priority wins |
| D.5 | Prompt cache-aware editing | 2-3 days | Server-side tool result deletion without cache break |
| D.6 | Session fingerprinting & drift detection | 0.5 day | Drift detected when context changes externally |
| D.7 | Swarm visualization (web UI multi-pane) | 3-5 days | Coordinator + worker status in web UI |
| D.8 | Proactive/autonomous agent mode | 3-5 days | Tick-based loop, Sleep pacing, focus-aware autonomy, anti-narration |
| D.9 | Away summary (session recap) | 0.5 day | 1-3 sentence recap when user returns after idle period |
| D.10 | Prompt suggestion service | 1-2 days | 1-3 clickable next-action suggestions after each turn |
| D.11 | Agent creation architect | 2-3 days | Meta-agent generates new agent configs from user descriptions |
| D.12 | Session search (cross-session retrieval) | 2-3 days | Find past sessions by topic/tag/branch, distinct from memory.search |

**Phase D done when:** Dream consolidation produces memories that improve retrieval relevance (measured via eval set). Proactive mode runs for 1 hour under token/turn/wall-clock caps without runaway. Session search returns relevant past sessions. Away summary and prompt suggestions render in web UI.

**Estimated total: 4-6 weeks**

---

## 6. Dependency Chain

```
Phase A (Safety + Correctness) — P0
 │  Query guard prevents session state corruption
 │  Message normalization stops 400 errors at the gateway
 │  Tool governance pipeline is the single execution path for all tools
 │  Streaming executor + event protocol is the core UX
 │  Trust boundary + deny-list gate untrusted workspaces
 │  Behavioral governance constrains LLM bad habits via prompt
 │
 ▼
Phase B (Cost + Performance) — P1
 │  Prompt cache saves money (needs stable tool dispatch from A)
 │  Compaction keeps long sessions viable (needs streaming from A)
 │  Large result governance prevents context blowup
 │  Hook expansion enables ecosystem (needs governance pipeline from A)
 │
 ▼
Phase C (Multi-Agent Orchestration) — P2
 │  Role-specialized agents need governance pipeline (A) for permission isolation
 │  Coordinator needs streaming executor (A) for parallel workers
 │  Task system needs query guard (A) for safe concurrent execution
 │  ToolSearch needs prompt compiler (B) for dynamic tool injection
 │  Fork subagents benefit from compaction (B) for cache sharing
 │
 ▼
Phase D (Long-Term Capabilities) — P3
 │  Dream consolidation needs memory taxonomy (B.7)
 │  Side-query classifier is optional, default OFF
 │  All other items are independent
```

---

## 7. Metrics: V1 vs V2

| Metric | V1 (Current) | V2 (Target) |
|--------|-------------|-------------|
| File execution | Local (basic) + Edge | Local (config-driven policy) + Edge (remote) |
| Tool concurrency | Sequential | Parallel (safe) + sequential (destructive) |
| Compaction | 1 strategy (sliding window) | 4 strategies + 2 controls (circuit breaker, diminishing returns) |
| System prompt | Recomputed every turn | Cached sections + dynamic boundary + diagnostics |
| Hook events | 9 (sync only) | 27 (async + timeout + blocking) |
| Permission modes | 1 (basic risk level) | 4 (default, plan, readonly, bypass) |
| Memory types | Flat | 4 (user, feedback, project, reference) |
| Agent patterns | Single + 1-level sub (blocking) | Coordinator + 4 specialized roles (Explore/Plan/Implement/Verify) + async workers + fork |
| Embedding | External API or local | Local by default (bge-small-en-v1.5, 384d, CPU) |
| Task tracking | None | Planning (persistent) + Runtime (ephemeral) |
| Error handling | Direct error surfacing | Withhold-recover + circuit breaker + backoff |
| Message validation | None | Pre-LLM normalization pipeline |
| Trust boundary | None | Per-workspace trust gating |
| Behavioral governance | None | Prompt-level constraints + tool usage grammar |
| Tool execution | Direct dispatch | 10-step governance pipeline (validate → classify → hook → permit → execute → post-hook) |
| Verification | None | Dedicated adversarial Verify agent role |
| Memory selection | Vector search only | Vector search + LLM relevance filtering (top-5) |
| Permission UX | Prompt with no context | Concurrent risk explainer alongside permission prompt |
| Session UX | No titles, no recap | Auto-generated titles + away summary + prompt suggestions |
| Autonomy | Cron (scheduled only) | Cron + proactive mode (tick-based, cache-aware, focus-aware) |
| Agent extensibility | Hardcoded roles | Agent creation architect (user-defined roles from description) |

---

## 8. Migration & Rollback Strategy

All schema changes use the existing SQLite migration system (`PRAGMA user_version` inside the migration transaction):

- **Forward-only migrations:** each migration increments `user_version` atomically within the DDL transaction. If the migration fails mid-way, the transaction rolls back and the version is not bumped — safe to retry.
- **Additive schema changes preferred:** new columns with defaults, new tables. Avoid renames or drops where possible.
- **Backfill in same transaction:** when adding columns or FTS tables, backfill existing rows within the migration transaction (learned from FTS5 backfill lesson).
- **Config changes:** new config fields always have `#[serde(default)]` so existing config files continue to work. Removed fields are silently ignored via `#[serde(deny_unknown_fields)]` NOT being set.
- **Rollback:** if a migration must be reversed, ship a new forward migration that undoes the change (no backward migration support — SQLite DDL is limited). Document breaking changes in CHANGELOG.

---

## 9. Files Changed Per Phase

### Phase A
| File | Action |
|------|--------|
| `crates/core/src/config.rs` | Modify — LocalModeConfig, WorkspaceTrust |
| `crates/gateway/src/local_tool_handler.rs` | Modify — config-driven workspace policy |
| `crates/gateway/src/local_tool_policy.rs` | Modify — workspace roots, denied paths, symlink protection |
| `crates/gateway/src/query_guard.rs` | Create — QueryGuardRegistry |
| `crates/gateway/src/server.rs` | Modify — executor init, trust init |
| `crates/gateway/src/ws.rs` | Modify — backpressure, graceful drain |
| `crates/gateway/src/node.rs` | Modify — dispatch routing |
| `crates/agent/src/streaming_executor.rs` | Create — StreamingToolExecutor |
| `crates/agent/src/message_validation.rs` | Create — normalize_for_api |
| `crates/agent/src/error_recovery.rs` | Create — ApiErrorRecovery, CircuitBreaker |
| `crates/agent/src/runtime.rs` | Modify — integrate executor, governance pipeline, validation |
| `crates/agent/src/context.rs` | Modify — behavioral governance prompt sections |
| `crates/core/src/traits.rs` | Modify — is_concurrent_safe() on InternalToolHandler |
| `crates/agent/src/risk_classifier.rs` | Create — speculative bash risk classifier |
| `crates/browser/src/` | Modify — runtime guardrails (loop detect, dialog dismiss, retry cap, timeout, metrics) |

### Phase B
| File | Action |
|------|--------|
| `crates/agent/src/prompt_cache.rs` | Create — PromptCache, CacheBreakReport |
| `crates/agent/src/compaction.rs` | Create — CompactionController |
| `crates/agent/src/result_store.rs` | Create — large result persistence with TTL/quota |
| `crates/agent/src/context.rs` | Modify — prompt compiler + compaction integration |
| `crates/core/src/hooks.rs` | Modify — expand to 27 events, async support |
| `crates/core/src/policy.rs` | Modify — PermissionMode enum |
| `crates/core/src/types.rs` | Modify — MemoryType enum |
| `crates/storage/` | Migration — memory_type column |
| `crates/memory/src/` | Modify — type-aware search |
| `crates/agent/src/tool_registry.rs` | Modify — ToolUseContext, permission checking |
| `crates/core/src/traits.rs` | Modify — `InternalToolHandler::handle()` signature change (add ToolUseContext param) |
| `crates/gateway/src/plugins/netprobe/mod.rs` | Modify — adapt to ToolUseContext |
| `crates/gateway/src/plugins/digest/mod.rs` | Modify — adapt to ToolUseContext |
| `crates/gateway/src/local_tool_handler.rs` | Modify — adapt to ToolUseContext |
| `crates/gateway/src/node.rs` | Modify — adapt NodeCommandHandler to ToolUseContext |
| `crates/gateway/src/plugin_api.rs` | Modify — hook delegation for new events |
| `crates/gateway/src/server.rs` | Modify — startup profiling, parallel prefetch |
| `crates/gateway/src/permission_explainer.rs` | Create — concurrent risk explanation side-query |
| `crates/gateway/src/handlers/chat.rs` | Modify — permission explainer integration, session title generation |
| `crates/storage/` | Migration — session title column (additive to memory_type migration) |
| `crates/memory/src/` | Modify — 2-stage recall+rerank selection |

### Phase C
| File | Action |
|------|--------|
| `crates/gateway/src/plugins/tasks/mod.rs` | Create — TaskPlugin |
| `crates/storage/` | Migration — session_tasks table |
| `crates/agent/src/subagent.rs` | Modify — async spawn, fork mode, AgentRole enum + tool filter |
| `crates/agent/src/runtime.rs` | Modify — task notification injection, role enforcement |
| `crates/agent/src/context.rs` | Modify — role-specific prompt sections (verify adversarial, coordinator anti-lazy) |
| `crates/agent/src/tool_search.rs` | Create — ToolSearch meta-tool |
| `crates/agent/src/tool_registry.rs` | Modify — deferred flag, search |

### Phase D
| File | Action |
|------|--------|
| `crates/gateway/src/handlers/cron.rs` | Modify — dream consolidation job |
| `crates/agent/src/context.rs` | Modify — dream agent prompt, classifier prompt, architect prompt |
| `crates/agent/src/proactive.rs` | Create — proactive agent loop, tick handling, Sleep pacing |
| `crates/core/src/config.rs` | Modify — settings precedence, dream config, proactive config |
| `crates/agent/src/runtime.rs` | Modify — session fingerprinting, away summary trigger |
| `crates/gateway/src/handlers/chat.rs` | Modify — away summary, prompt suggestions (session title already in Phase B) |
| `crates/gateway/src/handlers/agents.rs` | Modify — proactive mode lifecycle, agent architect |
| `crates/gateway/src/handlers/sessions.rs` | Modify — session search handler |
| `crates/storage/` | Migration — session search index only (session title column already in Phase B) |
| `web-ui/` | Modify — prompt suggestion chips, swarm pane, away summary card |

---

## 10. Verification

### Unit & Integration Tests

```bash
# Per-phase build verification
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Phase A specific
cargo test -p encmind-gateway -- local_tool query_guard
cargo test -p encmind-agent -- streaming_executor message_validation risk_classifier
cargo test -p encmind-browser -- guardrails loop_detect dialog_dismiss retry_cap action_timeout

# Phase B specific
cargo test -p encmind-agent -- prompt_cache compaction result_store
cargo test -p encmind-core -- hooks
cargo test -p encmind-memory -- memory_type memory_rerank
cargo test -p encmind-gateway -- permission_explainer session_title

# Phase C specific
cargo test -p encmind-gateway -- tasks
cargo test -p encmind-agent -- subagent tool_search

# Phase D specific
cargo test -p encmind-agent -- proactive dream
cargo test -p encmind-gateway -- session_search away_summary prompt_suggestion

# Full CI
cargo test --workspace --all-features
```

### Concurrency & Stress Tests (Phase A critical)

Phase A introduces concurrency-sensitive components that require targeted stress/race testing beyond standard unit tests:

| Component | Test | Method |
|-----------|------|--------|
| Query guard | Concurrent chat.send on same session | Spawn 10 tokio tasks sending to same session_id, verify serial execution + no dropped messages |
| Query guard | Independent sessions | Spawn 10 tasks on different session_ids, verify parallel execution |
| Streaming executor | Mixed safe/unsafe tools | Queue 5 safe + 2 unsafe tools, verify safe ran in parallel and unsafe blocked |
| Streaming executor | Cancellation mid-flight | Cancel parent token while tools executing, verify all child tokens cancelled + cleanup |
| Backpressure | Slow WS consumer | Send messages faster than consumer reads, verify bounded buffer (no OOM) |
| Graceful shutdown | SIGTERM during active tools | Send SIGTERM while tools in-flight, verify drain completes within timeout |
| Compaction circuit breaker | Repeated LLM failures | Mock LLM to fail 5 times, verify circuit opens after 3 and falls back to snip |
| Browser loop detection | Repeated identical actions | Submit same (url, selector, action) 4 times, verify abort after 3rd with loop_abort metric incremented |
| Browser dialog dismiss | JS alert during action | Inject alert via CDP, verify auto-dismiss + warning logged + dialog_dismissed metric incremented |
| Browser retry cap | Persistent selector failure | Mock selector miss 4 times, verify abort after 3rd attempt with screenshot taken |
| Browser action timeout | Slow page load | Mock page that never completes load, verify timeout fires at configured limit and action aborted cleanly |

Tests should use `loom` or manual `tokio::spawn` races with `tokio::time::pause()` for deterministic scheduling where possible.

---

## 11. Contributing

### Picking a task

1. Browse the phase tables in [Section 5](#5-implementation-plan). Each row is a self-contained work item with effort estimate and acceptance criteria.
2. **Phase A items are highest priority** — they're the safety and correctness foundation everything else depends on.
3. Open an issue referencing the section number (e.g., "Implement A.3: Tool execution governance pipeline").

### Pull request expectations

- Reference the doc section number in the PR title (e.g., `[A.3] Tool execution governance pipeline`)
- Include tests that match the **acceptance criteria** from the phase table — that's the definition of done
- For Phase A items, also check the **concurrency & stress tests** table in [Section 10](#10-verification) for required race/load tests
- Run the full verification suite before submitting:
  ```bash
  cargo build --workspace
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  ```

### What "done" means

The acceptance criteria in each phase table row is the exit condition. If the criteria says "concurrent chat.send serialized per session", the PR must include a test that spawns concurrent sends and verifies serialization. No acceptance criteria met = not ready for merge.

### Phase completion gates

Each phase has a "done when" statement. A phase is not complete until ALL items in that phase pass their acceptance criteria AND the phase gate condition is satisfied. See the gate statements after each phase table.

### Questions

Open an issue on the repo. Tag it with `question` and reference the relevant section number.
