# Digest Plugin

Text summarization, PDF extraction, and audio transcription.

## Tools

| Tool | Description | Parameters | Requires |
|------|-------------|------------|----------|
| `digest_summarize` | Summarize text (auto map-reduce for long docs) | `text` (required), `length` (short/medium/long, default medium) | LLM backend |
| `digest_url` | Fetch a URL and summarize its content | `url` (required), `length` (short/medium/long), `selector` (optional CSS selector for HTML extraction) | LLM backend |
| `digest_file` | Extract text from PDF or text files | `path` (required, absolute) | `enable_file_tools: true` |
| `digest_transcribe` | Transcribe audio via OpenAI Whisper | `path` (required, absolute), `language` (optional ISO-639/BCP-47) | `enable_file_tools: true` + `OPENAI_API_KEY` |

## Prerequisites

- LLM backend configured in `config.yaml` (for `digest_summarize` and `digest_url`)
- `OPENAI_API_KEY` env var (for `digest_transcribe`)
- `enable_file_tools: true` and `file_root` set (for `digest_file` and `digest_transcribe`)

## Configuration

Add to `~/.encmind/config.yaml`:

```yaml
plugins:
  digest:
    enabled: true
    max_single_pass_tokens: 8000
    max_map_reduce_chunks: 16
    enable_file_tools: false          # set true to enable digest_file + digest_transcribe
    file_root: "/data/files"          # required when enable_file_tools=true
    max_file_bytes: 52428800          # 50 MiB
    max_pdf_file_bytes: 20971520      # 20 MiB (must be <= max_file_bytes)
    max_audio_bytes: 26214400         # 25 MiB (must be <= max_file_bytes)
    max_pdf_pages: 200
    max_extracted_chars: 400000
    max_parallel_chunk_summaries: 4
    pdf_extract_timeout_secs: 30
    whisper_model: "whisper-1"
    whisper_timeout_secs: 180
    llm_timeout_secs: 120
    max_fetch_bytes: 524288           # for digest_url
    max_redirects: 5
```

### Config Reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Register Digest tools |
| `max_single_pass_tokens` | u32 | `8000` | Token threshold: below this uses single-pass, above uses map-reduce (min: 448) |
| `max_map_reduce_chunks` | u32 | `16` | Max chunks in map-reduce (range: 1..=128) |
| `whisper_model` | string | `"whisper-1"` | OpenAI Whisper model name |
| `enable_file_tools` | bool | `false` | Enable `digest_file` and `digest_transcribe` (secure-by-default) |
| `file_root` | path | `null` | Allowed directory for file access (required when `enable_file_tools=true`) |
| `max_file_bytes` | usize | `52428800` (50 MiB) | Max file size for text files |
| `max_pdf_file_bytes` | usize | `20971520` (20 MiB) | Max PDF file size (must be <= `max_file_bytes`) |
| `max_audio_bytes` | usize | `26214400` (25 MiB) | Max audio file size (must be <= `max_file_bytes`) |
| `max_pdf_pages` | u32 | `200` | Max PDF pages to extract |
| `max_extracted_chars` | usize | `400000` | Max characters in extracted text output |
| `max_parallel_chunk_summaries` | u32 | `4` | Concurrent chunk summarizations in map phase (range: 1..=16) |
| `pdf_extract_timeout_secs` | u64 | `30` | Timeout for PDF text extraction (range: 1..=300) |
| `whisper_timeout_secs` | u64 | `180` | HTTP timeout for Whisper API calls (range: 1..=600) |
| `llm_timeout_secs` | u64 | `120` | Timeout per LLM completion call (range: 1..=600) |
| `max_fetch_bytes` | usize | `524288` (512 KiB) | Max response body for `digest_url` fetch (range: 1..=16777216) |
| `max_redirects` | usize | `5` | Max redirect hops for `digest_url` (range: 1..=20) |

### Validation Rules

- `max_single_pass_tokens` >= 448
- `max_map_reduce_chunks` 1..=128
- `max_parallel_chunk_summaries` 1..=16
- `max_fetch_bytes` 1..=16777216
- `max_audio_bytes` <= `max_file_bytes`
- `max_pdf_file_bytes` <= `max_file_bytes`
- All byte/page/char limits must be > 0
- All timeout fields must be > 0 with documented upper bounds
- `whisper_model` must not be empty
- When `enable_file_tools=true`: `file_root` must be set, accessible, and an existing directory

## Environment Variables

| Variable | When needed | Description |
|----------|-----------|-------------|
| `OPENAI_API_KEY` | `digest_transcribe` | Required for Whisper API. Whitespace-only values are rejected. |

## How Tools Are Registered

- `digest_summarize` and `digest_url`: only registered when an LLM backend is available at startup. Log: `"summarize/url tools disabled (no LLM backend configured); restart gateway after configuring an LLM backend"`
- `digest_url`: additionally requires the fetch HTTP client to initialize successfully
- `digest_file` and `digest_transcribe`: only registered when `enable_file_tools: true`. Log: `"file tools disabled by configuration"`
- `digest_transcribe`: Whisper HTTP client is initialized lazily on first invocation (transient startup failures don't permanently disable it)

## Tool Details

### digest_summarize

- **Short text** (below `max_single_pass_tokens`): single LLM call
- **Long text**: automatic map-reduce pipeline:
  1. Split text into chunks (respecting UTF-8 boundaries)
  2. Summarize chunks in parallel (bounded by `max_parallel_chunk_summaries`)
  3. Staged reduce: merge chunk summaries, compressing oversized ones if needed
- Output includes:
  - `source_truncated`
  - `source_truncation.fetch_bytes_cap` (always `false` for `digest_summarize`)
  - `source_truncation.map_reduce_chunk_cap`
- Output token budget is length-aware: short=768, medium=2048, long=4096
- If single-pass fails with a context-limit error, automatically retries with map-reduce

### digest_url

- Fetches URL content via shared URL extractor (HTML to text, JSON pretty-print, text passthrough)
- Supports optional `selector` to summarize only a specific HTML region
- Fails fast if extracted content is empty (avoids wasted LLM calls)
- When fetch was truncated, adds a note to the summarization input so the LLM knows the content is incomplete
- Output includes:
  - `source_truncated` (overall source truncation signal)
  - `source_truncation.fetch_bytes_cap`
  - `source_truncation.map_reduce_chunk_cap`
  - `fetch.selector_applied` / `fetch.selector_ignored`

### digest_file

- **Supported formats:** `.pdf`, `.txt`, `.md`, `.csv`, `.json`
- **PDF extraction:** page-level extraction (only first `max_pdf_pages` pages), with configurable timeout and per-path concurrency limiting
- **Text files:** streaming UTF-8 decode with lossy fallback (invalid bytes replaced with `?`, replacement count reported)
- **Path security:** file path is canonicalized and checked against `file_root` (must be inside the allowed directory)
- **Output fields:** `content`, `pages`, `word_count`, `word_count_scope`, `truncated`, `encoding_lossy`, `encoding_replacement_count`

### digest_transcribe

- **Supported audio:** `.mp3`, `.mp4`, `.mpeg`, `.mpga`, `.m4a`, `.wav`, `.webm`
- **Language tag:** optional ISO-639/BCP-47 (e.g., `en`, `es`, `en-US`), validated before API call
- **Upload:** file is snapshotted to a temp file before upload, ensuring stable retries even if the source changes
- **Retries:** up to 2 retries on 5xx and 429 status codes, with Retry-After header support (seconds and HTTP-date formats)
- **Whisper client:** hardened (`no_proxy`, redirects disabled, configurable timeout), initialized lazily

## Manual Testing

```bash
# Start server with LLM backend
export ANTHROPIC_API_KEY="sk-ant-..."   # or OPENAI_API_KEY for OpenAI
export OPENAI_API_KEY="sk-..."          # also needed for digest_transcribe
cargo run -p encmind-cli -- --config ~/.encmind/config.yaml serve
# or 
encmind-core serve

# In another terminal
encmind-edge connect

# In another terminal, after pairing an edge device
encmind-edge chat

# Summarize text (triggers digest_summarize)
> Summarize this text: <paste a long article or document>

# Summarize a URL (triggers digest_url)
> Summarize this URL: https://example.com/article

# Extract text from a file (requires enable_file_tools + file_root)
> Extract text from /data/files/document.pdf

# Transcribe audio (requires enable_file_tools + file_root + OPENAI_API_KEY)
> Transcribe /data/files/recording.mp3

# Specify summary length
> Give me a short summary of this URL: https://example.com/long-report
```

## Automated Tests

```bash
# Digest unit tests (59 tests + 2 ignored integration tests)
cargo test -p encmind-gateway -- digest

# Config validation tests (19 tests)
cargo test -p encmind-core -- digest

# Integration tests (require real API keys + test files at /tmp/)
cargo test -p encmind-gateway -- --ignored
# Expects: OPENAI_API_KEY set, /tmp/test_audio.mp3, /tmp/test.pdf
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `digest_summarize` / `digest_url` not in tool list | No LLM backend configured | Add `llm:` section to config.yaml and restart |
| `digest_file` / `digest_transcribe` not in tool list | `enable_file_tools` is `false` (default) | Set `enable_file_tools: true` and `file_root` |
| `"OPENAI_API_KEY is empty"` | Env var not set or whitespace-only | `export OPENAI_API_KEY="sk-..."` |
| `"file_root must be set when enable_file_tools=true"` | Missing `file_root` in config | Set `file_root: "/path/to/allowed/directory"` |
| `"file path is outside the allowed file_root"` | Requested file not under `file_root` | Move the file inside `file_root` or adjust `file_root` |
| `"PDF extraction timed out after Ns"` | Large or complex PDF | Increase `pdf_extract_timeout_secs` (up to 300) |
| `"PDF extraction already in progress"` | Concurrent extraction for same file | Wait and retry; per-path semaphore prevents pile-up |
| `"max_single_pass_tokens is too low for map-reduce"` | Config below minimum (448) | Increase `max_single_pass_tokens` to at least 448 |
| `"unsupported audio format"` | File extension not in supported list | Use one of: mp3, mp4, mpeg, mpga, m4a, wav, webm |
| `"fetched content is empty after extraction"` | URL returned no extractable text | Check if the URL serves actual content (not just images/scripts) |

## Security

- **File tools disabled by default** (secure-by-default; must opt in via `enable_file_tools`)
- **Path traversal prevention:** file paths are canonicalized and checked with `starts_with(file_root)`
- **Capped, streaming file reads:** no unbounded memory allocation; size enforced during the read, not via a separate metadata check
- **PDF extraction:** per-path concurrency semaphore (prevents pile-up) + configurable timeout
- **Audio snapshot:** file is copied to temp before upload, preventing TOCTOU races
- **Whisper client:** `no_proxy`, redirect disabled, configurable timeout
- **LLM calls:** each call has a timeout with active cancellation on expiry
- **All fetch requests** (for `digest_url`) go through the EgressFirewall
- **Non-ASCII token estimation:** conservative penalty applied to avoid context-limit failures on CJK/emoji-heavy text
