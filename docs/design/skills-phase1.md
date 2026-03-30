# EncMind Skills Phase 1 — Design Document

## Overview

Three weeks of skill development to bring EncMind to feature parity with OpenClaw's most-used capabilities, while improving on their weaknesses (security, reliability, integration depth).

### Naming Convention

EncMind skills use distinct names to avoid confusion with OpenClaw equivalents:

| Week | EncMind Name | OpenClaw Equivalent | Why Different |
|------|-------------|-------------------|---------------|
| 1 | **NetProbe** | `web_search` (built-in) + Firecrawl | Unified search + fetch in one plugin |
| 1 | **Digest** | `summarize` + `nano-pdf` + `openai-whisper-api` | Unified summarize + PDF + transcribe |
| 2 | **WebAct** | Browser (built-in Playwright, 18 MCP tools) | Extends existing EncMind browser pool |
| 3 | **GWorkspace** | `gog` (CLI wrapper, 6 of 16 services) | Native Rust, no external CLI dependency |

### Architecture Principle

Many OpenClaw skills are **SKILL.md wrappers** — a markdown file that teaches the LLM to shell out to an external CLI binary. Common weaknesses in this model:

- CLI tools typically run with full user permissions
- External binary dependencies (Homebrew, Go, Python)
- Session resolution bugs between browser UI and CLI context
- OAuth token race conditions in cron/scheduled runs

EncMind skills are **compiled-in NativePlugins** — Rust code running inside the gateway process. They register tools via `PluginRegistrar`, use the existing `InternalToolHandler` trait, and benefit from:

- Type-safe parameter handling
- Shared connection pools and OAuth tokens
- Policy enforcement via `PolicyEnforcer`
- Sandboxed network access via `EgressFirewall`
- Persistent state via `PluginStateStore`

---

## Week 1: NetProbe (Search) + Digest (Summarize)

### 1.1 NetProbe — Web Search & Fetch

#### Functionality

| Tool | Parameters | Returns | Description |
|------|-----------|---------|-------------|
| `netprobe_search` | `query: String`, `max_results: u8` (default 5, max 10), `synthesize: Option<bool>` | JSON: `{ query, results: [{ title, url, snippet, score? }], synthesis }` | Search the web, return normalized search results and optional synthesized answer |
| `netprobe_fetch` | `url: String`, `selector: Option<String>` | `{ title, content: String, byte_length, truncated, content_type }` | Fetch a URL and extract readable content (HTML/text/JSON only) |

**Improvements over OpenClaw:**

| OpenClaw Issue | EncMind Fix |
|---------------|-------------|
| Brave Search API key required for setup, config corruption bug (#50261) | Multiple providers (Tavily, Brave, SearXNG) with graceful fallback |
| No answer synthesis — returns raw links | LLM-synthesized answer with cited sources |
| Proxy incompatibility on macOS | Uses `reqwest` with system proxy detection |
| `web_search` is platform-only, not a skill | NativePlugin — operator can disable, policy-gate, or configure |
| `xurl` (URL fetch) is a separate skill with external Go binary | `netprobe_fetch` built into same plugin, zero dependencies |
| Firecrawl requires separate API key + extension | Built-in URL fetch + readable HTML/text extraction |

#### Technical Design

**New files:**

```
crates/gateway/src/plugins/
├── mod.rs                  (plugin module index)
├── url_extract.rs          (~700+ lines, shared URL fetch + HTML/text extraction + tests)
└── netprobe.rs             (~1,250+ lines, plugin + provider adapters + tests)
```

**Modified existing files:**

```
crates/core/src/config.rs   (add NetProbeConfig)
```

`url_extract.rs` contains shared URL safety validation (scheme, userinfo, private-IP, redirect loop), HTML/text extraction, content-type gating, and CSS selector extraction. Both NetProbe and Digest import from here — neither depends on the other at runtime.

**Plugin structure:**

```rust
pub struct NetProbePlugin {
    config: NetProbeConfig,
    search_client: reqwest::Client,
    fetch_client: reqwest::Client,
    firewall: Arc<EgressFirewall>,
    runtime: Arc<RwLock<RuntimeResources>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetProbeConfig {
    /// Whether NetProbe tools are registered (default true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Search provider: "tavily", "brave", "searxng"
    #[serde(default)]
    pub provider: SearchProvider,
    /// Env var holding the API key (e.g. "TAVILY_API_KEY")
    pub api_key_env: Option<String>,
    /// For self-hosted SearXNG: base URL
    pub searxng_url: Option<String>,
    /// Whether to synthesize answers via LLM (default true)
    #[serde(default = "default_true")]
    pub synthesize: bool,
    /// Max content bytes for netprobe_fetch (default 512 KiB)
    #[serde(default = "default_max_fetch_bytes")]  // 524_288
    pub max_fetch_bytes: usize,
    /// Max redirect hops for netprobe_fetch (default 5, valid range 1..=20)
    #[serde(default = "default_max_redirects")]  // 5
    pub max_redirects: usize,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub enum SearchProvider {
    #[default]
    Tavily,
    Brave,
    Searxng,
}
```

**Search flow:**

```
Agent calls netprobe_search("best rust web frameworks 2026")
  │
  ▼
NetProbeSearchHandler::handle(input)
  │
  ├─ 1. EgressFirewall check (api.tavily.com allowed?)
  │
  ├─ 2. HTTP request to search provider API
  │     Client policy: redirects disabled (no automatic redirect follow)
  │     Tavily:  POST https://api.tavily.com/search
  │     Brave:   GET  https://api.search.brave.com/res/v1/web/search
  │     SearXNG: GET  {base_url}/search?q=...&format=json
  │
  ├─ 3. Parse provider response → Vec<SearchResult>
  │     SearchResult { title, url, snippet, score }
  │
  ├─ 4. If synthesize=true:
  │     Build prompt: "Given these search results for '{query}',
  │                    provide a concise answer citing sources."
  │     Call LlmBackend::complete() with search context
  │     Return { query, results, synthesis }
  │
  └─ 5. If synthesize=false:
        Return { query, results, synthesis: null } (raw results only)
```

**Fetch flow:**

```
Agent calls netprobe_fetch("https://example.com/article", selector: "article")
  │
  ▼
NetProbeFetchHandler::handle(input)
  │
  ├─ 1. URL safety validation:
  │     a. Scheme must be http/https
  │     b. Reject URL userinfo credentials
  │     c. Resolve host and reject loopback/private/link-local/unspecified IPs
  │     d. EgressFirewall check on host
  │
  ├─ 2. HTTP GET with timeout (30s)
  │     Headers: User-Agent
  │     Redirect policy: reqwest::redirect::Policy::none()
  │       — follow manually up to 5 hops
  │       — re-run step 1 validation on each Location target
  │       — this prevents SSRF via open-redirect chains
  │
  ├─ 3. Content-type check:
  │     text/html or application/xhtml+xml → HTML text extraction
  │     application/json or */*+json       → pretty-print JSON
  │     text/*                              → return raw text
  │     missing Content-Type                → sniff HTML/JSON/text, reject binary
  │     other                               → explicit unsupported content-type error
  │
  ├─ 4. HTML processing:
  │     a. If selector provided: extract matching elements only
  │        - invalid selector => error
  │        - selector matches 0 nodes => error
  │     b. Strip nav, footer, script, style, ads
  │     c. Normalize extracted text content
  │     d. Truncate at max_fetch_bytes
  │
  └─ 5. Return { title, content, byte_length, truncated, content_type }
```

**HTML extraction:** Use the `scraper` crate for DOM parsing, selector scoping, and text extraction (body-first, script/style/nav/footer removed).

**New dependencies:**

```toml
# In workspace Cargo.toml
scraper = "0.22"
url = "2"
```

**Plugin registration:**

```rust
impl NativePlugin for NetProbePlugin {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: "netprobe".into(),
            name: "NetProbe".into(),
            version: "0.1.0".into(),
            description: "Web search and URL content extraction".into(),
            kind: PluginKind::General,
            required: false,
        }
    }

    async fn register(&self, api: &mut dyn PluginRegistrar) {
        api.register_tool(
            "search",           // → auto-namespaced to "netprobe_search"
            "Search the web and return a synthesized answer with sources",
            SEARCH_PARAMS_JSON, // JSON Schema
            Arc::new(NetProbeSearchHandler { ... }),
        );
        api.register_tool(
            "fetch",            // → auto-namespaced to "netprobe_fetch"
            "Fetch a URL and extract readable content",
            FETCH_PARAMS_JSON,
            Arc::new(NetProbeFetchHandler { ... }),
        );
    }
}
```

**Config (config.yaml):**

```yaml
plugins:
  netprobe:
    enabled: true
    provider: tavily
    api_key_env: TAVILY_API_KEY
    synthesize: true
    max_fetch_bytes: 524288
    max_redirects: 5
```

#### Testing

| Test | Type | What it validates |
|------|------|-------------------|
| `search_tavily_parses_response` | Unit | Deserialize Tavily API JSON → `Vec<SearchResult>` |
| `search_brave_parses_response` | Unit | Deserialize Brave API JSON → `Vec<SearchResult>` |
| `search_searxng_parses_response` | Unit | Deserialize SearXNG JSON → `Vec<SearchResult>` |
| `search_clamps_max_results` | Unit | `max_results > 10` clamped to 10 |
| `search_rejects_invalid_max_results_type` | Unit | Non-integer `max_results` returns explicit error |
| `search_rejects_invalid_synthesize_type` | Unit | Non-boolean `synthesize` returns explicit error |
| `search_empty_query_error` | Unit | Empty/whitespace query returns error |
| `manual_redirects_follow_to_success_response` | Unit | Manual redirect loop resolves relative `Location` and returns final response |
| `manual_redirects_enforce_max_redirects` | Unit | Redirect loops fail once hop cap is exceeded |
| `manual_post_redirect_303_switches_to_get` | Unit | POST redirect behavior follows 303 -> GET semantics |
| `manual_post_redirect_301_switches_to_get` | Unit | POST redirect behavior follows 301 -> GET semantics |
| `manual_post_redirect_302_switches_to_get` | Unit | POST redirect behavior follows 302 -> GET semantics |
| `html_to_text_basic` | Unit | HTML input -> clean extracted text output |
| `html_to_text_with_selector` | Unit | Selector extracts only matching elements |
| `html_to_text_rejects_selector_when_no_matches` | Unit | Selector with no matching elements returns explicit error |
| `html_to_text_strips_scripts` | Unit | `<nav>`, `<script>`, `<style>` removed |
| `fetch_truncates_at_max_bytes` | Unit | Large content truncated at boundary |
| `fetch_rejects_unsupported_binary_content_types` | Unit | `image/*` and other binary content-types rejected |
| `fetch_missing_content_type_sniffs_html` | Unit | Missing `Content-Type` + HTML body -> treated as HTML |
| `fetch_missing_content_type_sniffs_uppercase_doctype_html` | Unit | Missing `Content-Type` + uppercase doctype -> treated as HTML |
| `fetch_missing_content_type_rejects_binary` | Unit | Missing `Content-Type` + binary body -> rejected |
| `synthesis_prompt_construction` | Unit | Search results → correct LLM prompt |
| `plugin_manifest_correct` | Unit | Plugin ID, name, version |
| `build_fetch_client_succeeds` | Unit | Fetch client initializes with expected baseline settings |
| `config_defaults` | Unit | Default provider = Tavily, synthesize = true |
| `config_searxng_requires_url` | Unit | SearXNG without URL → validation error |

**Current implementation: ~42 unit tests across `netprobe.rs` and `url_extract.rs` (plus optional integration tests).**

---

### 1.2 Digest — Summarize, PDF, Transcribe

#### Functionality

| Tool | Parameters | Returns | Description |
|------|-----------|---------|-------------|
| `digest_summarize` | `text: String`, `length: Option<String>` ("short"/"medium"/"long", default "medium") | `{ summary: String, word_count: u32 }` | Summarize provided text via LLM |
| `digest_url` | `url: String`, `length: Option<String>` | `{ summary: String, source_url: String, word_count: u32 }` | Fetch URL content, then summarize |
| `digest_file` | `path: String` | `{ content: String, pages: Option<u32>, word_count: u32 }` | Extract text from PDF or text file |
| `digest_transcribe` | `path: String`, `language: Option<String>` | `{ transcript: String, duration_secs: Option<f64> }` | Transcribe audio file via Whisper API |

**Improvements over OpenClaw:**

| OpenClaw Issue | EncMind Fix |
|---------------|-------------|
| `summarize` requires external CLI binary (`brew install steipete/tap/summarize`) | Built-in, zero external dependencies |
| `nano-pdf` requires Python + uv package manager | Pure Rust PDF extraction (`pdf-extract` crate) |
| `openai-whisper` (local) needs Python + ffmpeg + 3GB model download | API-only by default (lightweight), local mode planned |
| `openai-whisper-api` is a 30-line bash script with no retry/chunking | Rust with retries, file size validation, format detection |
| Four separate skills for overlapping functionality | One unified plugin with four tools |
| `summarize` always calls external LLM (no reuse of existing backend) | Reuses EncMind's configured `LlmBackend` — no extra API key |
| No token budget awareness | Map-reduce chunking for documents exceeding context window |

#### Technical Design

**New files:**

```
crates/gateway/src/plugins/digest.rs   (~500 lines, uses plugins::url_extract)
```

**Modified existing files:**

```
crates/core/src/config.rs              (add DigestConfig)
```

**Plugin structure:**

```rust
pub struct DigestPlugin {
    config: DigestConfig,
    http_client: reqwest::Client,
    llm: Arc<RwLock<Option<Arc<dyn LlmBackend>>>>,
    firewall: Arc<EgressFirewall>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DigestConfig {
    /// Max document tokens before map-reduce chunking (default 8000)
    #[serde(default = "default_8000")]
    pub max_single_pass_tokens: u32,
    /// Hard cap on map chunks to bound latency/cost (default 16)
    #[serde(default = "default_16")]
    pub max_map_reduce_chunks: u32,
    /// Whisper API model (default "whisper-1")
    #[serde(default = "default_whisper_model")]  // "whisper-1"
    pub whisper_model: String,
    /// Max audio file size in bytes (default 25 MiB — OpenAI limit)
    #[serde(default = "default_max_audio_bytes")]  // 26_214_400
    pub max_audio_bytes: usize,
    /// Max PDF pages to extract (default 200)
    #[serde(default = "default_200")]
    pub max_pdf_pages: u32,
    /// Allowed file read root (default: none — agent session dir only)
    pub file_root: Option<PathBuf>,
}
```

**Summarize flow (text + URL):**

```
Agent calls digest_summarize(text, length="short")
  │
  ▼
DigestSummarizeHandler::handle(input)
  │
  ├─ 1. Token count:
  │     a. Use provider tokenizer when available
  │     b. Fallback to conservative estimate for unknown models
  │
  ├─ 1b. Safety bounds:
  │     a. Cap input at max_map_reduce_chunks * max_single_pass_tokens
  │     b. If exceeded, truncate with explicit warning marker
  │
  ├─ 2a. If tokens <= max_single_pass_tokens:
  │      Single LLM call:
  │      "Summarize the following text in a {length} summary:\n\n{text}"
  │
  ├─ 2b. If tokens > max_single_pass_tokens (map-reduce):
  │      Split text into chunks of max_single_pass_tokens
  │      Map:   summarize each chunk independently (parallel futures)
  │      Reduce: summarize the concatenated chunk summaries
  │
  └─ 3. Return { summary, word_count }

digest_url flow:
  │
  ├─ 1. Call plugins::url_extract::fetch_and_extract(url, None)
  │     (shared module — same code netprobe_fetch uses, no runtime coupling)
  ├─ 2. Pass extracted content to digest_summarize
  └─ 3. Return { summary, source_url, word_count }
```

**PDF extraction flow:**

```
Agent calls digest_file("/tmp/uploads/report.pdf")
  │
  ▼
DigestFileHandler::handle(input)
  │
  ├─ 1. Path validation:
  │     a. Canonicalize path
  │     b. Check against file_root (path traversal prevention)
  │     c. Check file exists and size < max_pdf_pages * ~100KB
  │
  ├─ 2. Detect file type by extension:
  │     .pdf  → PDF extraction
  │     .txt/.md/.csv/.json → read as text
  │     other → error with supported formats list
  │
  ├─ 3. PDF extraction (pdf-extract crate):
  │     a. Open PDF, get page count
  │     b. If pages > max_pdf_pages → error
  │     c. Extract text page by page
  │     d. Concatenate with page markers: "\n--- Page N ---\n"
  │     e. Basic cleanup: collapse whitespace, fix encoding
  │
  └─ 4. Return { content, pages, word_count }
```

**Audio transcription flow:**

```
Agent calls digest_transcribe("/tmp/uploads/meeting.m4a", language="en")
  │
  ▼
DigestTranscribeHandler::handle(input)
  │
  ├─ 1. Path validation (same as file handler)
  │
  ├─ 2. File checks:
  │     a. Extension must be: mp3, m4a, wav, webm, mp4, mpeg, mpga, oga, ogg, flac
  │     b. Size must be <= max_audio_bytes (25 MiB)
  │
  ├─ 3. Read OPENAI_API_KEY from env
  │     (or reuse existing OpenAI provider key if configured)
  │
  ├─ 4. Multipart POST to https://api.openai.com/v1/audio/transcriptions
  │     Form fields: file, model, language (optional), response_format="text"
  │     Retry: up to 2 retries with exponential backoff on 5xx
  │
  └─ 5. Return { transcript, duration_secs }
```

**New dependencies:**

```toml
# In workspace Cargo.toml
pdf-extract = "0.7"
```

**Config (config.yaml):**

```yaml
plugins:
  digest:
    max_single_pass_tokens: 8000
    max_map_reduce_chunks: 16
    whisper_model: whisper-1
    max_audio_bytes: 26214400
    max_pdf_pages: 200
```

#### Testing

| Test | Type | What it validates |
|------|------|-------------------|
| `summarize_short_text` | Unit | Short text → single-pass LLM call |
| `summarize_length_variants` | Unit | "short"/"medium"/"long" → different prompts |
| `summarize_map_reduce_chunking` | Unit | Long text splits into chunks correctly |
| `summarize_enforces_chunk_cap` | Unit | Oversized input capped at configured max chunks |
| `summarize_empty_text_error` | Unit | Empty input → error |
| `url_fetches_then_summarizes` | Unit | URL → fetch → summarize pipeline |
| `url_fetch_failure_propagates` | Unit | Bad URL → error (not crash) |
| `file_pdf_extracts_text` | Unit | Sample PDF → extracted text with page markers |
| `file_txt_reads_directly` | Unit | .txt file → raw content |
| `file_csv_reads_directly` | Unit | .csv file → raw content |
| `file_path_traversal_blocked` | Unit | `../../etc/passwd` → error |
| `file_unsupported_extension` | Unit | .exe → error with supported list |
| `file_max_pages_exceeded` | Unit | 500-page PDF → error |
| `transcribe_validates_extension` | Unit | .pdf → error (not audio) |
| `transcribe_validates_file_size` | Unit | 30 MiB → error |
| `transcribe_builds_multipart` | Unit | Correct multipart form construction |
| `transcribe_retries_on_5xx` | Unit | Mock 503 → retry → success |
| `transcribe_missing_api_key` | Unit | No OPENAI_API_KEY → clear error |
| `config_defaults` | Unit | Default values correct |
| `plugin_manifest_correct` | Unit | Plugin ID, name, version |
| `tool_registration` | Unit | Four tools registered |
| `transcribe_integration` | Integration (#[ignore]) | Real Whisper API with short audio |
| `pdf_integration` | Integration (#[ignore]) | Real PDF file → non-empty text |

**Total: ~21 unit + 2 integration = 23 tests**

---

## Week 2: WebAct — Browser Automation

### Functionality

**Existing EncMind browser tools** (keep as-is):

| Tool | Description |
|------|-------------|
| `browser_navigate` | Navigate to URL, return page title |
| `browser_screenshot` | Take PNG screenshot, return base64 |
| `browser_get_text` | Extract visible text from page |
| `browser_act` | Session-scoped interactive actions (click, type, press, select, upload, wait, screenshot, get_text, eval, close) |

**New WebAct tools** (higher-level automation):

| Tool | Parameters | Returns | Description |
|------|-----------|---------|-------------|
| `webact_fill_form` | `session_id: String`, `fields: Vec<{selector, value}>` | `{ filled: u32, errors: Vec<String> }` | Batch-fill form fields by CSS selector |
| `webact_extract_table` | `session_id: String`, `selector: String` | `{ headers: Vec<String>, rows: Vec<Vec<String>> }` | Extract HTML table to structured JSON |
| `webact_extract_links` | `session_id: String`, `selector: Option<String>` | `Vec<{ text, href }>` | Extract all links (optionally scoped) |
| `webact_watch` | `url: String`, `selector: String`, `interval_minutes: u32`, `session_id: Option<String>` | `{ watch_id: String }` | Monitor a page element for changes (timer-based). `session_id` required for authenticated pages |
| `webact_watch_list` | (none) | `Vec<{ watch_id, url, selector, last_hash, changes }>` | List active page watches |
| `webact_watch_remove` | `watch_id: String` | `{ removed: bool }` | Stop watching a page element |
| `webact_run_script` | `session_id: String`, `script: String`, `args: Option<Vec<Value>>` | `{ result: Value }` | Execute JavaScript in page context |
| `webact_pdf` | `session_id: String`, `path: String` | `{ path: String, bytes: u64 }` | Save current page as PDF |

**Improvements over OpenClaw:**

| OpenClaw Feature | OpenClaw Approach | EncMind Improvement |
|-----------------|-------------------|---------------------|
| 18 MCP tools | Playwright-based, session per CDP URL | Chromiumoxide, session per agent session |
| `fill_form` | Batch fill with type normalization | Same + CSS selector (not uid-based) |
| `take_snapshot` | 3 modes (aria, AI, role) | Not needed — `browser_get_text` + `extract_table` covers use cases |
| `evaluate_script` | JS eval in page | Same (`webact_run_script`) |
| Cookie/storage management | get/set/clear | Not in v1 — add if requested |
| Device emulation | locale, timezone, geolocation | Not in v1 — add if requested |
| Page monitoring | None built-in (blogwatcher is RSS only) | `webact_watch` with timer + selector + content hash |
| DOM snapshots | Accessibility tree (2000 nodes max) | Not needed — text extraction is sufficient |
| Network monitoring | Request/response/error buffers | Not in v1 — add if requested |

#### Technical Design

**New files:**

```
crates/browser/src/actions.rs       (~400 lines, composite actions)
crates/gateway/src/plugins/webact.rs (~500 lines, plugin + handlers)
```

**Modified existing files:**

```
crates/browser/src/pool.rs          (add has_existing_session, session_generation to SessionBrowserManager)
crates/core/src/config.rs           (add WebActConfig)
```

**Plugin structure:**

```rust
pub struct WebActPlugin {
    config: WebActConfig,
    browser_pool: Arc<BrowserPool>,
    session_manager: Arc<SessionBrowserManager>,
    firewall: Arc<EgressFirewall>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebActConfig {
    #[serde(default = "default_50")]
    pub max_watches: u32,
    #[serde(default = "default_60")]
    pub watch_poll_interval_secs: u64,
    #[serde(default = "default_4")]
    pub watch_max_concurrency: u32,
    #[serde(default = "default_2")]
    pub watch_stale_warn_multiplier: u32,
    /// What to do when an authenticated watch's session expires.
    #[serde(default)]
    pub watch_session_fallback: WatchSessionFallback,
    #[serde(default = "default_5000")]
    pub max_script_timeout_ms: u64,
    #[serde(default = "default_pdf_output_dir")]  // "/tmp/encmind-pdfs"
    pub pdf_output_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub enum WatchSessionFallback {
    /// Pause the watch and emit an event. Default — fail-closed.
    #[default]
    Pause,
    /// Downgrade to unauthenticated mode with a warning.
    Downgrade,
}
```

**Key design decision:** WebAct uses the existing `SessionBrowserManager` for session-scoped pages. New tools operate on the same page the agent is already using via `browser_act`.

`webact_watch` supports two explicit modes:
- `session_id: None` → unauthenticated background watch using `BrowserPool`
- `session_id: Some(id)` → authenticated watch using the session's page/cookies via `SessionBrowserManager`

**Session expiry handling:** `SessionBrowserManager` evicts idle sessions (30s cycle). A watch with `interval_minutes=60` will outlive its session. Default behavior is **fail-closed** (`WatchSessionFallback::Pause`):

Detection contract — `SessionBrowserManager` is extended with:
```rust
/// Returns true if session_id has an active, non-evicted page.
/// Does NOT create a new page — purely a lookup.
pub fn has_existing_session(&self, session_id: &str) -> bool;

/// Returns the monotonic generation counter for a session.
/// Increments each time a session is evicted and re-created.
/// Returns None if the session has never existed.
pub fn session_generation(&self, session_id: &str) -> Option<u64>;
```

The watch stores `session_generation` at creation time. On each timer tick:
1. Call `has_existing_session(session_id)` — if `false`, session was evicted.
2. If `true`, also compare `session_generation()` with stored value — if it changed, the session was recycled (new page, no cookies from the original login).
3. On mismatch: **pause the watch** (sets `status: "paused_session_expired"`) and emit a `"watch_session_expired"` event with `watch_id`.
4. The watch does **not** silently downgrade — that would produce incorrect results for login-gated pages.

When `WatchSessionFallback::Downgrade` is configured, step 3 instead acquires a fresh page from `BrowserPool` (unauthenticated) and continues with a `"watch_session_downgraded"` warning.

**Fill form flow:**

```
Agent calls webact_fill_form(session_id, fields)
  │
  ▼
WebActFillFormHandler::handle(input)
  │
  ├─ 1. Acquire SessionPageGuard from SessionBrowserManager
  │
  ├─ 2. For each field in fields:
  │     a. Find element by CSS selector (page.find_element)
  │     b. Detect element type:
  │        <input type="text/email/..."> → element.type_str(value)
  │        <input type="checkbox"> → click if value != current state
  │        <select> → find <option> matching value, click
  │        <textarea> → element.type_str(value)
  │     c. Track success/failure per field
  │
  └─ 3. Return { filled, errors }
```

**Extract table flow:**

```
Agent calls webact_extract_table(session_id, selector="table.results")
  │
  ▼
WebActExtractTableHandler::handle(input)
  │
  ├─ 1. Acquire SessionPageGuard
  │
  ├─ 2. Execute JS in page context:
  │     const table = document.querySelector(selector);
  │     const headers = [...table.querySelectorAll('th')].map(th => th.textContent);
  │     const rows = [...table.querySelectorAll('tr')].map(tr =>
  │       [...tr.querySelectorAll('td')].map(td => td.textContent)
  │     );
  │     return { headers, rows };
  │
  └─ 3. Return { headers, rows }
```

**Watch flow (background timer):**

```
Agent calls webact_watch(url, selector, interval_minutes=60, session_id?)
  │
  ▼
WebActWatchHandler::handle(input)
  │
  ├─ 1. Generate watch_id (ULID)
  │
  ├─ 2. Immediately fetch + hash:
  │     a. If session_id provided: use SessionBrowserManager page for that session
  │     b. Else: acquire page from BrowserPool (unauthenticated watch)
  │     c. Navigate to URL
  │     d. Extract text of matching selector
  │     e. SHA-256 hash the text
  │     f. Release page back to pool
  │
  ├─ 3. Store in PluginStateStore:
  │     key: "watch:{watch_id}"
  │     value: { url, selector, session_id, session_generation, interval_minutes,
  │              last_hash, last_check, change_count }
  │     (session_generation is null when session_id is absent)
  │
  └─ 4. Return { watch_id }

Background timer (registered via register_timer, runs every 60s):
  │
  ├─ 1. List all "watch:*" keys from PluginStateStore
  │
  ├─ 2. For each watch where elapsed >= interval_minutes:
  │     a. If session_id is set:
  │        i.  Call has_existing_session(session_id)
  │        ii. If false, or session_generation() != stored session_generation:
  │            - WatchSessionFallback::Pause  → set status "paused_session_expired",
  │              emit "watch_session_expired" event, skip this watch
  │            - WatchSessionFallback::Downgrade → acquire page from BrowserPool,
  │              emit "watch_session_downgraded" warning, continue
  │        iii. Otherwise: use SessionBrowserManager page for this session
  │     b. If session_id is absent: acquire page from BrowserPool
  │     c. Navigate to URL (timeout 30s)
  │     d. Extract text of selector
  │     e. SHA-256 hash
  │     f. Compare with last_hash
  │     g. If changed:
  │        - Increment change_count
  │        - Update last_hash
  │        - Emit hook event (agent can react)
  │     h. Update last_check
  │     i. Release page
  │
  ├─ 3. If no page slot is available, keep watch in backlog queue
  │     and increment "watch_deferred" metric
  │
  └─ 4. Emit warning if a watch misses SLA (e.g. no check for > 2x interval)
```

**Improvement over OpenClaw's `blogwatcher` and EncMind's existing `web-watch`:**
- `blogwatcher` only handles RSS feeds, not arbitrary web pages
- `web-watch` (WASM skill) uses HTTP GET and hashes the raw body — cannot handle JavaScript-rendered pages
- `webact_watch` uses Chromium rendering, extracts specific elements by CSS selector, then hashes. This works on SPAs and dynamic pages. For login-gated pages, caller must pass `session_id`.

**Policy gating:**

| Tool | Risk Level | Rationale |
|------|-----------|-----------|
| `webact_fill_form` | Sensitive | Writes data to external sites |
| `webact_extract_table` | Low | Read-only extraction |
| `webact_extract_links` | Low | Read-only extraction |
| `webact_watch` | Low | Background monitoring, read-only |
| `webact_run_script` | Critical | Arbitrary JS execution |
| `webact_pdf` | Low | Read-only file generation |

**Config (config.yaml):**

```yaml
plugins:
  webact:
    max_watches: 50
    watch_poll_interval_secs: 60
    watch_max_concurrency: 4
    watch_stale_warn_multiplier: 2
    watch_session_fallback: pause   # pause (fail-closed) | downgrade (unauthenticated)
    max_script_timeout_ms: 5000
    pdf_output_dir: /tmp/encmind-pdfs
```

#### Testing

| Test | Type | What it validates |
|------|------|-------------------|
| `fill_form_text_inputs` | Unit | Text/email/password fields filled correctly |
| `fill_form_checkbox_toggle` | Unit | Checkbox toggled to target state |
| `fill_form_select_option` | Unit | Dropdown option selected by value |
| `fill_form_missing_selector` | Unit | Invalid selector → error in errors array |
| `fill_form_partial_success` | Unit | 3 fields, 1 fails → filled=2, errors=[1] |
| `extract_table_basic` | Unit | Simple HTML table → headers + rows |
| `extract_table_no_headers` | Unit | Table without `<th>` → empty headers, data in rows |
| `extract_table_nested` | Unit | Nested tables → only outer table extracted |
| `extract_table_missing_selector` | Unit | No matching element → empty result |
| `extract_links_all` | Unit | All `<a href>` extracted |
| `extract_links_scoped` | Unit | Only links within selector scope |
| `watch_creates_entry` | Unit | New watch stored in state store |
| `watch_deduplicates_url_selector` | Unit | Same URL+selector → update, not duplicate |
| `watch_list_returns_all` | Unit | List all active watches |
| `watch_remove_deletes` | Unit | Remove by ID → deleted from store |
| `watch_timer_detects_change` | Unit | Different hash → change_count incremented |
| `watch_timer_skips_unchanged` | Unit | Same hash → no event emitted |
| `watch_timer_respects_interval` | Unit | Check skipped if interval not elapsed |
| `watch_timer_pool_exhausted` | Unit | No available browser → skip gracefully |
| `watch_with_session_id_uses_session_page` | Unit | Authenticated watch bound to session cookies |
| `watch_session_expired_pauses` | Unit | Dead session + `pause` mode → watch paused + event emitted |
| `watch_session_expired_downgrades` | Unit | Dead session + `downgrade` mode → unauthenticated + warning |
| `watch_stale_warn_emitted` | Unit | Deferred checks emit stale warning after threshold |
| `run_script_returns_value` | Unit | JS eval → JSON result |
| `run_script_timeout` | Unit | Infinite loop → timeout error |
| `run_script_policy_critical` | Unit | Policy enforcer classifies as Critical |
| `pdf_saves_file` | Unit | Page → PDF file at specified path |
| `pdf_path_traversal_blocked` | Unit | `../../etc/` → error |
| `plugin_manifest_correct` | Unit | Plugin metadata |
| `tool_registration` | Unit | All 8 tools registered |
| `config_defaults` | Unit | Default values correct |
| `watch_integration` | Integration (#[ignore]) | Real page watch cycle |
| `extract_table_integration` | Integration (#[ignore]) | Real page table extraction |

**Total: ~31 unit + 2 integration = 33 tests**

---

## Week 3: GWorkspace — Google Workspace

### Functionality

| Tool | Parameters | Returns | Description |
|------|-----------|---------|-------------|
| `gws_calendar_list` | `days: u32` (default 7), `calendar_id: Option<String>` | `Vec<{ id, title, start, end, location, attendees }>` | List upcoming events |
| `gws_calendar_create` | `title, start, end, description?, location?, attendees?: Vec<String>` | `{ event_id, link }` | Create calendar event |
| `gws_calendar_update` | `event_id, title?, start?, end?, description?, location?` | `{ updated: bool }` | Update event fields |
| `gws_calendar_delete` | `event_id` | `{ deleted: bool }` | Delete/cancel event |
| `gws_contacts_search` | `query: String`, `max_results: u32` (default 20) | `Vec<{ name, email, phone? }>` | Search Google Contacts |
| `gws_docs_read` | `doc_id: String` | `{ title, content: String (markdown) }` | Read Google Doc as markdown |
| `gws_drive_search` | `query: String`, `max_results: u32` (default 10) | `Vec<{ id, name, mime_type, modified, link }>` | Search Google Drive files |
| `gws_sheets_read` | `spreadsheet_id: String`, `range: String` | `{ headers?, rows: Vec<Vec<String>> }` | Read spreadsheet range |
| `gws_sheets_append` | `spreadsheet_id: String`, `range: String`, `rows: Vec<Vec<String>>` | `{ appended_rows: u32 }` | Append rows to sheet *(only registered when `enable_sheet_writes=true`)* |

**Improvements over OpenClaw's GOG:**

| OpenClaw (GOG) Issue | EncMind (GWorkspace) Fix |
|--------------------|-------------------------|
| External CLI binary dependency (`brew install steipete/tap/gogcli`) | Native Rust HTTP calls to Google APIs |
| OAuth stored in OS keyring (session bugs #44456 between CLI/browser) | Reuses existing GmailAdapter OAuth2 token — single source of truth |
| Token refresh race conditions in cron (#43557) | Shared `Arc<RwLock<(token, expiry)>>` with 60s refresh buffer |
| Only 6 of 16 Google services documented in SKILL.md | Ship 5 services (Calendar, Contacts, Docs, Drive, Sheets) — most-used |
| No Calendar delete/cancel | Full CRUD on calendar events |
| Google OAuth app review barrier (#39842) | Same OAuth credentials as Gmail — may avoid additional review if scopes are pre-approved in the existing OAuth consent screen |
| `--body` doesn't unescape `\n` | Not applicable — structured JSON input |
| Docs: no in-place editing | Same limitation — read-only. Clearly documented. |

#### Technical Design

**New files:**

```
crates/channels/src/google_api.rs      (~300 lines, shared Google API client)
crates/gateway/src/plugins/gworkspace.rs (~600 lines, plugin + handlers)
```

**Modified existing files:**

```
crates/core/src/config.rs              (add GWorkspaceConfig)
```

**Plugin structure:**

```rust
pub struct GWorkspacePlugin {
    config: GWorkspaceConfig,
    google_client: Arc<GoogleApiClient>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GWorkspaceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Override Gmail OAuth credentials (falls back to Gmail env vars if absent)
    pub client_id_env: Option<String>,
    pub client_secret_env: Option<String>,
    pub refresh_token_env: Option<String>,
    #[serde(default = "default_primary")]  // "primary"
    pub default_calendar: String,
    #[serde(default = "default_gworkspace_scopes")]
    pub scopes: Vec<String>,
    /// Register gws_sheets_append tool (default false — opt-in)
    #[serde(default)]
    pub enable_sheet_writes: bool,
}

fn default_gworkspace_scopes() -> Vec<String> {
    vec![
        "calendar.events".into(),
        "contacts.readonly".into(),
        "documents.readonly".into(),
        "drive.readonly".into(),
        "spreadsheets.readonly".into(),
    ]
}
```

**Key design: shared OAuth2 token with Gmail**

The GmailAdapter already manages OAuth2 token refresh for Gmail API access. GWorkspace reuses the exact same `client_id`, `client_secret`, and `refresh_token` — just requests additional scopes. This avoids:
- Duplicate OAuth credentials
- Token refresh races (single token source)
- Separate OAuth app setup (though adding sensitive scopes like Calendar may still require Google verification, depending on app publishing status)

```
┌──────────────────────────────────────────────────────┐
│                  Shared OAuth2 Token                  │
│          Arc<RwLock<Option<(String, Instant)>>>       │
│                                                       │
│   GmailAdapter ──────────┤                            │
│   (channel: poll/send)   │                            │
│                          ├── refresh_access_token()   │
│   GWorkspacePlugin ──────┤   POST oauth2.googleapis   │
│   (tools: calendar,      │   .com/token               │
│    contacts, docs,       │                            │
│    drive, sheets)        │                            │
└──────────────────────────────────────────────────────┘
```

**Shared Google API client (`google_api.rs`):**

```rust
/// Shared Google API HTTP client with OAuth2 token management.
pub struct GoogleApiClient {
    http: reqwest::Client,
    token: Arc<RwLock<Option<(String, Instant)>>>,
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

impl GoogleApiClient {
    /// Create from existing Gmail credentials.
    pub fn from_gmail_credentials(
        client_id: String,
        client_secret: String,
        refresh_token: String,
    ) -> Self { ... }

    /// Get a valid access token, refreshing if needed.
    pub async fn access_token(&self) -> Result<String, ChannelError> { ... }

    /// Make an authenticated GET request to a Google API endpoint.
    pub async fn get(&self, url: &str) -> Result<serde_json::Value, ChannelError> { ... }

    /// Make an authenticated POST request.
    pub async fn post(&self, url: &str, body: &serde_json::Value)
        -> Result<serde_json::Value, ChannelError> { ... }

    /// Make an authenticated PATCH request.
    pub async fn patch(&self, url: &str, body: &serde_json::Value)
        -> Result<serde_json::Value, ChannelError> { ... }

    /// Make an authenticated DELETE request.
    pub async fn delete(&self, url: &str) -> Result<(), ChannelError> { ... }
}
```

**Calendar API flow:**

```
Agent calls gws_calendar_list(days=7)
  │
  ▼
GwsCalendarListHandler::handle(input)
  │
  ├─ 1. Calculate time range:
  │     time_min = now (RFC3339)
  │     time_max = now + days (RFC3339)
  │
  ├─ 2. GET https://www.googleapis.com/calendar/v3/calendars/{id}/events
  │     ?timeMin={}&timeMax={}&singleEvents=true&orderBy=startTime&maxResults=50
  │     Authorization: Bearer {access_token}
  │
  ├─ 3. Parse response → Vec<CalendarEvent>
  │     Map each item: { id, summary→title, start.dateTime→start,
  │                       end.dateTime→end, location, attendees[].email }
  │
  └─ 4. Return events JSON

Agent calls gws_calendar_create(title, start, end, ...)
  │
  ├─ 1. Validate: start < end, ISO 8601 format
  │
  ├─ 2. POST https://www.googleapis.com/calendar/v3/calendars/primary/events
  │     Body: { summary, start: {dateTime}, end: {dateTime},
  │             description, location, attendees: [{email}] }
  │
  └─ 3. Return { event_id, link: htmlLink }
```

**Google API endpoints used:**

| Service | Endpoint | Scope Required |
|---------|----------|---------------|
| Calendar | `googleapis.com/calendar/v3/` | `calendar.events` |
| Contacts | `people.googleapis.com/v1/people:searchContacts` | `contacts.readonly` |
| Docs | `docs.googleapis.com/v1/documents/{id}` | `documents.readonly` |
| Drive | `googleapis.com/drive/v3/files` | `drive.readonly` |
| Sheets (read) | `sheets.googleapis.com/v4/spreadsheets/{id}` | `spreadsheets.readonly` |
| Sheets (append) | `sheets.googleapis.com/v4/spreadsheets/{id}:append` | `spreadsheets` |

**Policy gating:**

| Tool | Risk Level | Rationale |
|------|-----------|-----------|
| `gws_calendar_list` | Low | Read-only |
| `gws_calendar_create` | Sensitive | Creates events visible to attendees |
| `gws_calendar_update` | Sensitive | Modifies events |
| `gws_calendar_delete` | Sensitive | Deletes events |
| `gws_contacts_search` | Low | Read-only |
| `gws_docs_read` | Low | Read-only |
| `gws_drive_search` | Low | Read-only |
| `gws_sheets_read` | Low | Read-only |
| `gws_sheets_append` | Sensitive | Writes data to spreadsheet |

**Config (config.yaml):**

```yaml
plugins:
  gworkspace:
    enabled: true
    # Reuses Gmail OAuth credentials — no additional config needed
    # unless using separate credentials:
    # client_id_env: GOOGLE_CLIENT_ID
    # client_secret_env: GOOGLE_CLIENT_SECRET
    # refresh_token_env: GOOGLE_REFRESH_TOKEN
    default_calendar: primary
    scopes:
      - calendar.events
      - contacts.readonly
      - documents.readonly
      - drive.readonly
      - spreadsheets.readonly
    enable_sheet_writes: false
```

**Scope upgrade path:**

The existing Gmail config uses `gmail.readonly` + `gmail.send` scopes. GWorkspace adds Calendar/Contacts/Docs/Drive/Sheets scopes. Users must re-authorize with the additional scopes. Some Google Cloud app configurations may require additional verification steps for sensitive scopes, depending on app publishing status and user type:

```bash
# One-time: re-authorize with expanded scopes
# (handled via channels.login RPC or CLI --refresh-token)
```

The `GoogleApiClient` is constructed at gateway startup. If GWorkspace scopes are not authorized, API calls return 403 and the tool handler returns a clear scope-specific error (for example: "Google Calendar scope not authorized. Re-run channels.login with calendar scope.").

**`enable_sheet_writes` enforcement:** When `enable_sheet_writes=false` (the default), `gws_sheets_append` is **not registered** during `NativePlugin::register()`. The agent never sees the tool, avoiding wasted LLM tool calls. When the operator sets `enable_sheet_writes=true` and adds the `spreadsheets` scope (replacing `spreadsheets.readonly`), the tool appears on next gateway restart.

**Startup validation:** `GWorkspaceConfig::validate()` is called during gateway initialization (before plugin registration). It checks:
- If `enable_sheet_writes=true` but `scopes` contains `spreadsheets.readonly` instead of `spreadsheets` → **fail-fast** with a clear error: `"enable_sheet_writes requires 'spreadsheets' scope, but config has 'spreadsheets.readonly'"`.
- If `scopes` list is empty → warning (plugin will register but all tools will 403 at runtime).

This prevents silent misconfiguration where the tool is registered but every call fails with a 403.

#### Testing

| Test | Type | What it validates |
|------|------|-------------------|
| `calendar_list_parses_events` | Unit | Google Calendar API JSON → `Vec<CalendarEvent>` |
| `calendar_list_empty` | Unit | No events → empty vec |
| `calendar_list_all_day_events` | Unit | `date` field (no `dateTime`) handled |
| `calendar_create_validates_times` | Unit | start >= end → error |
| `calendar_create_builds_request` | Unit | Correct POST body construction |
| `calendar_update_partial_fields` | Unit | Only changed fields in PATCH body |
| `calendar_delete_builds_request` | Unit | Correct DELETE URL |
| `contacts_search_parses_response` | Unit | People API JSON → `Vec<Contact>` |
| `contacts_search_empty_query` | Unit | Empty query → error |
| `docs_read_parses_body` | Unit | Docs API JSON → markdown text |
| `docs_read_handles_formatting` | Unit | Bold/italic/links → markdown |
| `drive_search_parses_files` | Unit | Drive API JSON → `Vec<DriveFile>` |
| `drive_search_builds_query` | Unit | Query string → `q` parameter |
| `sheets_read_parses_range` | Unit | Sheets API JSON → headers + rows |
| `sheets_read_empty_range` | Unit | Empty range → empty rows |
| `sheets_append_builds_body` | Unit | Rows → correct API body |
| `google_api_client_token_refresh` | Unit | Expired token → refresh called |
| `google_api_client_token_cache` | Unit | Valid token → no refresh |
| `google_api_client_403_scope_error` | Unit | 403 → clear scope error message |
| `google_api_client_retry_on_5xx` | Unit | 503 → retry once |
| `plugin_manifest_correct` | Unit | Plugin metadata |
| `tool_registration_default` | Unit | 8 tools registered when `enable_sheet_writes=false` |
| `tool_registration_writes_enabled` | Unit | 9 tools registered when `enable_sheet_writes=true` |
| `config_defaults` | Unit | Default calendar = "primary", `enable_sheet_writes=false` |
| `config_validates_writes_scope_mismatch` | Unit | `enable_sheet_writes=true` + `spreadsheets.readonly` → startup error |
| `config_reuses_gmail_creds` | Unit | Falls back to Gmail env vars |
| `calendar_integration` | Integration (#[ignore]) | Real Calendar API list |
| `contacts_integration` | Integration (#[ignore]) | Real Contacts search |

**Total: ~26 unit + 2 integration = 28 tests**

---

## Summary

### Deliverables by Week

New files only; `config.rs` and other existing files are modified in place, not counted here.

| Week | Plugin | Tools | New Files | Est. Lines | Tests |
|------|--------|-------|-----------|-----------|-------|
| 1 | NetProbe (uses url_extract) | 2 | 3 (mod.rs, url_extract.rs, netprobe.rs) | ~1,650 | 39 |
| 1 | Digest | 4 | 1 (digest.rs) | ~500 | 23 |
| 2 | WebAct | 8 | 2 (actions.rs, webact.rs) | ~950 | 33 |
| 3 | GWorkspace | 9 (8 default + 1 opt-in) | 2 (google_api.rs, gworkspace.rs) | ~900 | 28 |
| **Total** | **4 plugins** | **23 tools** | **8 new files** | **~4,000** | **123** |

### New Dependencies

| Crate | Version | Used By | Purpose |
|-------|---------|---------|---------|
| `scraper` | 0.22 | NetProbe | CSS selector extraction |
| `url` | 2.x | NetProbe/Core config | URL parsing + scheme validation |
| `pdf-extract` | 0.7 | Digest | PDF text extraction |

### Config Additions (config.yaml)

```yaml
plugins:
  netprobe:
    provider: tavily
    api_key_env: TAVILY_API_KEY
    synthesize: true
    max_fetch_bytes: 524288
    max_redirects: 5

  digest:
    max_single_pass_tokens: 8000
    max_map_reduce_chunks: 16
    whisper_model: whisper-1
    max_audio_bytes: 26214400
    max_pdf_pages: 200

  webact:
    max_watches: 50
    watch_poll_interval_secs: 60
    watch_max_concurrency: 4
    watch_stale_warn_multiplier: 2
    watch_session_fallback: pause
    max_script_timeout_ms: 5000
    pdf_output_dir: /tmp/encmind-pdfs

  gworkspace:
    enabled: true
    default_calendar: primary
    scopes:
      - calendar.events
      - contacts.readonly
      - documents.readonly
      - drive.readonly
      - spreadsheets.readonly
    # Require explicit opt-in before enabling write APIs
    enable_sheet_writes: false
```

### Rollout, Observability, and Guardrails

**Rollout plan (per plugin):**
- Stage 0: `enabled: false`, run unit tests only.
- Stage 1: enable in dry-run/read-only mode for internal sessions.
- Stage 2: enable for a small operator allowlist (5 to 10% traffic).
- Stage 3: full enablement with kill switch retained.

**Kill switches:**
- Global: `plugins.<name>.enabled=false`.
- Per-tool: policy denylist by tool name.
- Runtime: disable plugin immediately on repeated 5xx/429 bursts.

**Observability SLOs:**
- Success rate by tool (`5m`, `1h`, `24h` windows)
- p50/p95 latency by tool
- token/cost usage for synthesis/summarization calls
- watch backlog and deferred-check counts
- scope-error counters (Google 403 per scope)

**Abuse and budget controls:**
- Per-session QPS and concurrency caps per tool group
- Daily external API budget caps (search/transcribe/google)
- Per-run max tool-call limits and cumulative timeout ceilings
- Domain allowlist defaults for outbound search/fetch

### OpenClaw vs EncMind Comparison

| Dimension | OpenClaw | EncMind |
|-----------|----------|--------|
| Skill format | Many skills are SKILL.md wrappers that call external tools | Compiled NativePlugin (type-safe) |
| Dependencies | Often depends on external binaries per skill | Zero external dependencies |
| Sandboxing | Depends on called tooling; shell-outs commonly inherit user perms | EgressFirewall + PolicyEnforcer |
| OAuth | Per-CLI binary token storage (race conditions) | Shared `Arc<RwLock>` token (single source) |
| Search | Platform-only, Brave API key required | Plugin with 3 providers + fallback |
| Summarize | 4 separate skills, 4 external binaries | 1 plugin, 4 tools, zero binaries |
| Browser | 18 MCP tools (Playwright) | 12 tools (chromiumoxide) + page watching |
| Google Workspace | 6 of 16 services via CLI | 5 services, native HTTP, shared Gmail OAuth |
| Page monitoring | RSS feeds only (blogwatcher) | Real browser rendering + CSS selector targeting |
| PDF extraction | Python package (nano-pdf) | Pure Rust (pdf-extract) |
| Transcription | Python + 3GB model download OR bash curl script | Whisper API with retries + validation |
