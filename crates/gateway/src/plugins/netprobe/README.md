# NetProbe Plugin

Web search and URL content extraction.

## Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `netprobe_search` | Search the web via Tavily, Brave, or SearXNG | `query` (string, required), `max_results` (int 1-10, default 5), `synthesize` (bool, default from config) |
| `netprobe_fetch` | Fetch and extract content from a URL | `url` (string, required), `selector` (string, optional CSS selector) |

## Prerequisites

- LLM backend configured in `config.yaml` (required for synthesis)
- API key for your chosen search provider:
  - **Tavily** (default): `export TAVILY_API_KEY="tvly-..."`
  - **Brave**: `export BRAVE_API_KEY="BSA..."`
  - **SearXNG**: self-hosted instance, no API key needed

## Configuration

Add to `~/.encmind/config.yaml`:

```yaml
plugins:
  netprobe:
    enabled: true
    provider: tavily
    # api_key_env: "TAVILY_API_KEY"   # custom env var name (overrides auto-detection)
    # searxng_url: "https://search.example.com"  # required when provider=searxng
    synthesize: true
    max_fetch_bytes: 524288
    max_provider_body_bytes: 1048576
    max_fetch_output_chars: 20000
    max_redirects: 5
    post_redirect_compat_301_302_to_get: false
```

### Config Reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Register NetProbe tools |
| `provider` | string | `tavily` | Search backend: `tavily`, `brave`, or `searxng` |
| `api_key_env` | string | `null` | Custom env var name for API key (overrides default per-provider lookup) |
| `searxng_url` | string | `null` | Base URL for self-hosted SearXNG (required when `provider=searxng`) |
| `synthesize` | bool | `true` | Generate an LLM-synthesized answer from search results |
| `max_fetch_bytes` | int | `524288` (512 KiB) | Max response body size for URL fetch (range: 1..=16777216) |
| `max_provider_body_bytes` | int | `1048576` (1 MiB) | Max provider API response body size parsed for search results/errors (range: 1..=8388608) |
| `max_fetch_output_chars` | int | `20000` | Max characters returned in `netprobe_fetch` `content` output (range: 1..=200000) |
| `max_redirects` | int | `5` | Max redirect hops to follow (upper bound: 20) |
| `post_redirect_compat_301_302_to_get` | bool | `false` | When `true`, convert POST to GET on 301/302 redirects (browser-compat mode). When `false`, preserve POST semantics and only convert on 303. |

### Validation Rules

- `max_fetch_bytes` must be 1..=16777216
- `max_provider_body_bytes` must be 1..=8388608
- `max_fetch_output_chars` must be 1..=200000
- `max_redirects` must be 1..=20
- When `provider=searxng`: `searxng_url` is required, must be http/https, must include a host, must not contain userinfo, query parameters, or fragments

## Search Providers

| Provider | Config value | Default env var | Signup |
|----------|-------------|----------------|--------|
| Tavily | `tavily` | `TAVILY_API_KEY` | https://tavily.com |
| Brave | `brave` | `BRAVE_API_KEY` | https://brave.com/search/api/ |
| SearXNG | `searxng` | none (self-hosted) | — |

**SearXNG notes:**
- Path is normalized automatically: both `https://host` and `https://host/search` produce the correct `/search` endpoint
- Query parameters (`?q=...&format=json&pageno=1`) are constructed programmatically

## How Tools Are Registered

- `netprobe_search` is only registered if the HTTP search client initializes successfully
- `netprobe_fetch` is only registered if the HTTP fetch client initializes successfully
- If either client fails to build (rare — typically TLS backend issues), the affected tool is skipped with a warning in server logs
- Both tools are skipped entirely when `enabled: false`

## Manual Testing

```bash
# Set API key and start server
export TAVILY_API_KEY="tvly-..."
export ANTHROPIC_API_KEY="sk-ant-..."   # or OPENAI_API_KEY for LLM backend
cargo run -p encmind-cli -- --config ~/.encmind/config.yaml serve
# or 
encmind-core serve

# In another terminal
encmind-edge connect

# In another terminal, after pairing an edge device
encmind-edge chat

# Try search (triggers netprobe_search)
> Search for Rust async runtime comparison

# Try fetch (triggers netprobe_fetch)
> Fetch the content of https://example.com

# Try search with synthesis disabled
> Search for "tokio vs async-std" without synthesizing an answer
```

## Automated Tests

```bash
# NetProbe unit tests (28 tests)
cargo test -p encmind-gateway -- netprobe

# Config validation tests (8 tests)
cargo test -p encmind-core -- netprobe

# All together
cargo test -p encmind-gateway -p encmind-core -- netprobe
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `"API key not set; checked env vars: TAVILY_API_KEY"` | Env var not exported | `export TAVILY_API_KEY="tvly-..."` |
| `netprobe_search` not in tool list | Search client init failed, or no API key available | Check server startup logs for `"search tool will be disabled"` warnings |
| `netprobe_fetch` not in tool list | Fetch client init failed | Check server startup logs for `"fetch tool will be disabled"` warnings |
| `"egress firewall blocked"` | Provider API domain not reachable through firewall | Add provider domains to `security.egress_firewall.global_allowlist` |
| `"unsupported content-type"` on fetch | URL returns binary content (images, video, etc.) | Only HTML, JSON, and `text/*` MIME types are supported |
| `"too many redirects"` | Redirect chain exceeds `max_redirects` | Increase `max_redirects` (up to 20) or check the URL |
| `"cross-origin redirect blocked"` | Provider API redirected to a different domain | This is a security feature for credentialed providers; check provider URL config |

## Security

- All outbound requests are validated by the EgressFirewall (every redirect hop is re-checked)
- Cross-origin redirects are blocked for credentialed providers (Tavily, Brave) to prevent API key leakage
- URLs with embedded credentials (`user:pass@host`) are rejected at every stage
- Provider response bodies are capped at `max_provider_body_bytes` (default 1 MiB) to prevent memory exhaustion
- Fetch response bodies are capped at `max_fetch_bytes` (default 512 KiB)
- Fetch tool output content is additionally capped at `max_fetch_output_chars` (default 20,000 chars)
- HTTP clients use `no_proxy()` to ensure deterministic egress routing
- Redirect following is disabled at the client level; redirects are handled manually with per-hop firewall validation
- Synthesis prompt marks all web snippets as untrusted data with instruction-following guardrails
- Titles, snippets, and queries are truncated before inclusion in the synthesis prompt
