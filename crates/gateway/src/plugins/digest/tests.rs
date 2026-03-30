use super::*;
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use encmind_agent::tool_registry::ToolRegistry;
use encmind_core::error::LlmError;
use encmind_core::hooks::{HookHandler, HookPoint};
use encmind_core::plugin::{
    GatewayMethodHandler, NativeChannelTransform, NativePluginTimer, PluginRegistrar,
};
use encmind_core::traits::{CompletionDelta, ModelInfo};
use futures::stream;

struct StubLlmBackend {
    response: String,
}

#[async_trait]
impl LlmBackend for StubLlmBackend {
    async fn complete(
        &self,
        _messages: &[Message],
        _params: CompletionParams,
        _cancel: CancellationToken,
    ) -> Result<
        Pin<Box<dyn futures::Stream<Item = Result<CompletionDelta, LlmError>> + Send>>,
        LlmError,
    > {
        Ok(Box::pin(stream::iter(vec![Ok(CompletionDelta {
            text: Some(self.response.clone()),
            thinking: None,
            tool_use: None,
            finish_reason: Some(encmind_core::traits::FinishReason::Stop),
        })])))
    }

    async fn count_tokens(&self, _messages: &[Message]) -> Result<u32, LlmError> {
        Ok(0)
    }

    fn model_info(&self) -> ModelInfo {
        ModelInfo {
            id: "stub".to_string(),
            name: "stub".to_string(),
            context_window: 8192,
            provider: "test".to_string(),
            supports_tools: false,
            supports_streaming: true,
            supports_thinking: false,
        }
    }
}

struct QueueLlmBackend {
    responses: Mutex<VecDeque<String>>,
    call_count: AtomicUsize,
}

impl QueueLlmBackend {
    fn new(responses: Vec<String>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from(responses)),
            call_count: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl LlmBackend for QueueLlmBackend {
    async fn complete(
        &self,
        _messages: &[Message],
        _params: CompletionParams,
        _cancel: CancellationToken,
    ) -> Result<
        Pin<Box<dyn futures::Stream<Item = Result<CompletionDelta, LlmError>> + Send>>,
        LlmError,
    > {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let next = self
            .responses
            .lock()
            .expect("queue lock poisoned")
            .pop_front()
            .ok_or_else(|| LlmError::StreamError("queue exhausted".to_string()))?;

        Ok(Box::pin(stream::iter(vec![Ok(CompletionDelta {
            text: Some(next),
            thinking: None,
            tool_use: None,
            finish_reason: Some(encmind_core::traits::FinishReason::Stop),
        })])))
    }

    async fn count_tokens(&self, _messages: &[Message]) -> Result<u32, LlmError> {
        Ok(0)
    }

    fn model_info(&self) -> ModelInfo {
        ModelInfo {
            id: "queue".to_string(),
            name: "queue".to_string(),
            context_window: 8192,
            provider: "test".to_string(),
            supports_tools: false,
            supports_streaming: true,
            supports_thinking: false,
        }
    }
}

struct RecordingRegistrar {
    plugin_id: String,
    tools: Vec<String>,
}

impl RecordingRegistrar {
    fn new(plugin_id: &str) -> Self {
        Self {
            plugin_id: plugin_id.to_string(),
            tools: Vec::new(),
        }
    }
}

impl PluginRegistrar for RecordingRegistrar {
    fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    fn register_tool(
        &mut self,
        name: &str,
        _description: &str,
        _parameters: serde_json::Value,
        _handler: Arc<dyn encmind_agent::tool_registry::InternalToolHandler>,
    ) -> Result<(), PluginError> {
        self.tools.push(name.to_string());
        Ok(())
    }

    fn register_hook(
        &mut self,
        _point: HookPoint,
        _priority: i32,
        _handler: Arc<dyn HookHandler>,
    ) -> Result<(), PluginError> {
        Ok(())
    }

    fn register_gateway_method(
        &mut self,
        _method: &str,
        _handler: Arc<dyn GatewayMethodHandler>,
    ) -> Result<(), PluginError> {
        Ok(())
    }

    fn register_channel_transform(
        &mut self,
        _channel: &str,
        _priority: i32,
        _handler: Arc<dyn NativeChannelTransform>,
    ) -> Result<(), PluginError> {
        Ok(())
    }

    fn register_timer(
        &mut self,
        _name: &str,
        _interval_secs: u64,
        _handler: Arc<dyn NativePluginTimer>,
    ) -> Result<(), PluginError> {
        Ok(())
    }
}

#[test]
fn plugin_manifest_correct() {
    let config = DigestConfig::default();
    let fw_cfg = encmind_core::config::EgressFirewallConfig::default();
    let firewall = Arc::new(EgressFirewall::new(&fw_cfg));
    let runtime = Arc::new(RwLock::new(RuntimeResources {
        llm_backend: None,
        tool_registry: Arc::new(encmind_agent::tool_registry::ToolRegistry::new()),
    }));
    let plugin = DigestPlugin::new(config, firewall, runtime);
    let manifest = plugin.manifest();
    assert_eq!(manifest.id, "digest");
    assert_eq!(manifest.kind, PluginKind::General);
    assert!(!manifest.required);
}

#[test]
fn parse_length_defaults_to_medium() {
    let input = json!({});
    assert_eq!(parse_length(&input).unwrap(), "medium");
}

#[test]
fn parse_length_valid_variants() {
    assert_eq!(parse_length(&json!({"length": "short"})).unwrap(), "short");
    assert_eq!(
        parse_length(&json!({"length": "medium"})).unwrap(),
        "medium"
    );
    assert_eq!(parse_length(&json!({"length": "long"})).unwrap(), "long");
}

#[test]
fn parse_length_invalid_rejected() {
    let err = parse_length(&json!({"length": "extra_long"})).unwrap_err();
    assert!(err.to_string().contains("invalid length"), "err = {err}");
}

#[test]
fn parse_length_rejects_non_string() {
    let err = parse_length(&json!({"length": 42})).unwrap_err();
    assert!(err.to_string().contains("must be a string"), "err = {err}");
}

#[test]
fn map_chunk_budget_reserves_prompt_overhead() {
    let config = DigestConfig {
        max_single_pass_tokens: 8_000,
        ..Default::default()
    };
    let map_output_budget = clamp_generation_tokens(&config, map_output_max_tokens("medium"));
    assert_eq!(max_generation_tokens(&config), 7_616);
    assert_eq!(map_output_budget, 768);
    assert_eq!(
        map_chunk_input_budget_tokens(&config, map_output_budget),
        6_848
    );
    assert_eq!(map_chunk_byte_budget(&config, map_output_budget), 27_392);
    assert_eq!(clamp_generation_tokens(&config, 4_096), 4_096);
}

#[test]
fn map_chunk_budget_never_exceeds_tiny_contexts() {
    let config = DigestConfig {
        max_single_pass_tokens: 128,
        ..Default::default()
    };
    let map_output_budget = clamp_generation_tokens(&config, map_output_max_tokens("medium"));
    assert_eq!(max_generation_tokens(&config), 1);
    assert_eq!(map_chunk_input_budget_tokens(&config, map_output_budget), 1);
    assert_eq!(map_chunk_byte_budget(&config, map_output_budget), 4);
    assert_eq!(clamp_generation_tokens(&config, 4_096), 1);
}

#[test]
fn estimate_tokens_basic() {
    // 400 chars → ~100 tokens
    let text = "a".repeat(400);
    assert_eq!(estimate_tokens(&text), 100);
}

#[test]
fn estimate_tokens_non_ascii_penalty() {
    let text = "測".repeat(100); // non-ASCII-heavy input
                                 // Base byte estimate is 75 (300 bytes / 4). Penalty should push this upward.
    assert_eq!(estimate_tokens(&text), 100);
}

#[tokio::test]
async fn llm_complete_errors_on_stream_failure_after_partial_output() {
    struct FailingStreamLlmBackend;

    #[async_trait]
    impl LlmBackend for FailingStreamLlmBackend {
        async fn complete(
            &self,
            _messages: &[Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<
            Pin<Box<dyn futures::Stream<Item = Result<CompletionDelta, LlmError>> + Send>>,
            LlmError,
        > {
            let stream = stream::iter(vec![
                Ok(CompletionDelta {
                    text: Some("partial ".to_string()),
                    thinking: None,
                    tool_use: None,
                    finish_reason: None,
                }),
                Err(LlmError::StreamError("boom".to_string())),
            ]);
            Ok(Box::pin(stream))
        }

        async fn count_tokens(&self, _messages: &[Message]) -> Result<u32, LlmError> {
            Ok(0)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "failing".to_string(),
                name: "failing".to_string(),
                context_window: 8192,
                provider: "test".to_string(),
                supports_tools: false,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    let runtime = Arc::new(RwLock::new(RuntimeResources {
        llm_backend: Some(Arc::new(FailingStreamLlmBackend)),
        tool_registry: Arc::new(ToolRegistry::new()),
    }));
    let err = llm_complete(&runtime, "hello", 256, 30).await.unwrap_err();
    assert!(err.to_string().contains("LLM stream error"), "err = {err}");
}

#[tokio::test]
async fn llm_complete_times_out_on_stalled_stream() {
    struct PendingStreamLlmBackend;

    #[async_trait]
    impl LlmBackend for PendingStreamLlmBackend {
        async fn complete(
            &self,
            _messages: &[Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<
            Pin<Box<dyn futures::Stream<Item = Result<CompletionDelta, LlmError>> + Send>>,
            LlmError,
        > {
            Ok(Box::pin(
                stream::pending::<Result<CompletionDelta, LlmError>>(),
            ))
        }

        async fn count_tokens(&self, _messages: &[Message]) -> Result<u32, LlmError> {
            Ok(0)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "pending".to_string(),
                name: "pending".to_string(),
                context_window: 8192,
                provider: "test".to_string(),
                supports_tools: false,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    let runtime = Arc::new(RwLock::new(RuntimeResources {
        llm_backend: Some(Arc::new(PendingStreamLlmBackend)),
        tool_registry: Arc::new(ToolRegistry::new()),
    }));
    let err = llm_complete(&runtime, "hello", 256, 1).await.unwrap_err();
    assert!(
        err.to_string().contains("timed out"),
        "expected timeout error, got: {err}"
    );
}

#[tokio::test]
async fn llm_complete_timeout_signals_cancel_token() {
    struct CancelAwarePendingBackend {
        cancelled: Arc<AtomicBool>,
    }

    #[async_trait]
    impl LlmBackend for CancelAwarePendingBackend {
        async fn complete(
            &self,
            _messages: &[Message],
            _params: CompletionParams,
            cancel: CancellationToken,
        ) -> Result<
            Pin<Box<dyn futures::Stream<Item = Result<CompletionDelta, LlmError>> + Send>>,
            LlmError,
        > {
            let cancelled = self.cancelled.clone();
            tokio::spawn(async move {
                cancel.cancelled().await;
                cancelled.store(true, Ordering::SeqCst);
            });
            Ok(Box::pin(
                stream::pending::<Result<CompletionDelta, LlmError>>(),
            ))
        }

        async fn count_tokens(&self, _messages: &[Message]) -> Result<u32, LlmError> {
            Ok(0)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "cancel-aware".to_string(),
                name: "cancel-aware".to_string(),
                context_window: 8192,
                provider: "test".to_string(),
                supports_tools: false,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    let cancelled = Arc::new(AtomicBool::new(false));
    let runtime = Arc::new(RwLock::new(RuntimeResources {
        llm_backend: Some(Arc::new(CancelAwarePendingBackend {
            cancelled: cancelled.clone(),
        })),
        tool_registry: Arc::new(ToolRegistry::new()),
    }));

    let err = llm_complete(&runtime, "hello", 256, 1).await.unwrap_err();
    assert!(
        err.to_string().contains("timed out"),
        "expected timeout error, got: {err}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        cancelled.load(Ordering::SeqCst),
        "expected cancellation token to be signaled on timeout"
    );
}

#[tokio::test]
async fn summarize_text_compresses_single_oversized_stage() {
    let backend = Arc::new(QueueLlmBackend::new(vec![
        "x".repeat(320),             // map summary (oversized for reduce budget)
        "compressed summary".into(), // single-stage compression output
        "final summary".into(),      // final reduce output
    ]));
    let runtime = Arc::new(RwLock::new(RuntimeResources {
        llm_backend: Some(backend.clone()),
        tool_registry: Arc::new(ToolRegistry::new()),
    }));
    let config = DigestConfig {
        max_single_pass_tokens: 450,
        max_map_reduce_chunks: 1,
        max_parallel_chunk_summaries: 1,
        ..Default::default()
    };
    let input = "A".repeat(2_000);

    let summary = summarize_text(&runtime, &config, &input, "long", false)
        .await
        .expect("single-stage compression path should succeed");

    assert_eq!(summary, "final summary");
    assert_eq!(backend.calls(), 3, "expected map + compress + final reduce");
}

#[tokio::test]
async fn summarize_text_allows_same_stage_count_when_tokens_shrink() {
    // max_single_pass_tokens=1300 → output_budget(short)=768, reduce_input_budget=1300-768-384=148.
    // Map phase returns 2 summaries of 800 chars each ≈ 200+16=216 tokens.
    // Together: 432 > 148 → doesn't fit. Each individually: 216 > 148 → triggers compression.
    // Compressed outputs ("short a"/"short b") ≈ 2+16=18 tokens each → 36 total ≤ 148 → fits.
    let backend = Arc::new(QueueLlmBackend::new(vec![
        "x".repeat(800),        // map summary #1 (oversized)
        "y".repeat(800),        // map summary #2 (oversized)
        "short a".into(),       // compress #1 → fits budget
        "short b".into(),       // compress #2 → fits budget
        "merged ab".into(),     // reduce_summary_batch merges compressed pair
        "final summary".into(), // final reduce
    ]));
    let runtime = Arc::new(RwLock::new(RuntimeResources {
        llm_backend: Some(backend.clone()),
        tool_registry: Arc::new(ToolRegistry::new()),
    }));
    let config = DigestConfig {
        max_single_pass_tokens: 1300,
        max_map_reduce_chunks: 2,
        max_parallel_chunk_summaries: 1,
        ..Default::default()
    };
    let input = "A".repeat(6_000);

    let summary = summarize_text(&runtime, &config, &input, "short", false)
        .await
        .expect("staged reduce should succeed when token load shrinks");

    assert_eq!(summary, "final summary");
    // map(2) + compress(2) + reduce_batch(1) + final_reduce(1) = 6 calls
    assert_eq!(
        backend.calls(),
        6,
        "expected map(2) + compress(2) + batch_reduce(1) + final_reduce(1)"
    );
}

#[test]
fn split_into_chunks_basic() {
    let text = "abcdefghij"; // 10 chars
    let chunks = split_into_chunks(text, 4);
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0], "abcd");
    assert_eq!(chunks[1], "efgh");
    assert_eq!(chunks[2], "ij");
}

#[test]
fn split_into_chunks_unicode_safe() {
    // Japanese characters: each is 3 bytes in UTF-8
    let text = "\u{3042}\u{3044}\u{3046}\u{3048}\u{304A}"; // あいうえお
                                                           // Each char is 3 bytes, total 15 bytes. Chunk size 4 bytes.
    let chunks = split_into_chunks(text, 4);
    // Should not panic and should produce valid strings.
    for chunk in &chunks {
        assert!(!chunk.is_empty());
        // Verify it's valid UTF-8 (it is, since we only slice at char boundaries).
        let _: &str = chunk;
    }
}

#[test]
fn split_into_chunks_empty_text() {
    let chunks = split_into_chunks("", 100);
    assert!(chunks.is_empty());
}

#[test]
fn file_path_traversal_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("safe");
    std::fs::create_dir_all(&root).unwrap();
    // Create a file outside the root.
    let outside = dir.path().join("secret.txt");
    std::fs::write(&outside, "secret").unwrap();

    let err = validate_file_path(outside.to_str().unwrap(), Some(&root)).unwrap_err();
    assert!(
        err.to_string().contains("outside the allowed file_root"),
        "err = {err}"
    );
}

#[test]
fn file_path_inside_root_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let file = root.join("test.txt");
    std::fs::write(&file, "hello").unwrap();
    let canonical_root = root.canonicalize().unwrap();

    let result = validate_file_path(file.to_str().unwrap(), Some(&canonical_root));
    assert!(result.is_ok());
}

#[test]
fn file_unsupported_extension_error() {
    // We test the extension check logic by running the handler check manually.
    let ext = "exe";
    let is_pdf = ext == "pdf";
    let is_text = TEXT_EXTENSIONS.contains(&ext);
    assert!(!is_pdf);
    assert!(!is_text);
}

#[test]
fn validate_audio_extension_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.pdf");
    std::fs::write(&file, "fake").unwrap();
    let err = validate_audio_file(&file, 1024).unwrap_err();
    assert!(
        err.to_string().contains("unsupported audio format"),
        "err = {err}"
    );
}

#[test]
fn validate_audio_extension_missing_extension_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test");
    std::fs::write(&file, "fake").unwrap();
    let err = validate_audio_file(&file, 1024).unwrap_err();
    assert!(err.to_string().contains("has no extension"), "err = {err}");
}

#[test]
fn validate_audio_extension_accepted() {
    let dir = tempfile::tempdir().unwrap();
    for ext in &["mp3", "m4a", "wav"] {
        let file = dir.path().join(format!("test.{ext}"));
        std::fs::write(&file, "fake audio data").unwrap();
        assert!(
            validate_audio_file(&file, 1024).is_ok(),
            "extension {ext} should be accepted"
        );
    }
}

#[test]
fn validate_transcribe_language_accepts_common_codes() {
    assert_eq!(
        validate_transcribe_language(Some("en".to_string())).unwrap(),
        Some("en".to_string())
    );
    assert_eq!(
        validate_transcribe_language(Some("en-US".to_string())).unwrap(),
        Some("en-US".to_string())
    );
    assert_eq!(validate_transcribe_language(None).unwrap(), None);
}

#[test]
fn validate_transcribe_language_rejects_invalid_tags() {
    let err = validate_transcribe_language(Some("english".to_string())).unwrap_err();
    assert!(err.to_string().contains("invalid language"), "err = {err}");

    let err = validate_transcribe_language(Some("e$".to_string())).unwrap_err();
    assert!(err.to_string().contains("invalid language"), "err = {err}");

    let err = validate_transcribe_language(Some("en-@@".to_string())).unwrap_err();
    assert!(
        err.to_string().contains("invalid language tag"),
        "err = {err}"
    );
}

#[test]
fn validate_audio_size_exceeded() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("big.mp3");
    std::fs::write(&file, vec![0u8; 1024]).unwrap();
    let err = validate_audio_file(&file, 512).unwrap_err();
    assert!(err.to_string().contains("max_audio_bytes"), "err = {err}");
}

#[test]
fn validate_file_size_rejects_large_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("big.txt");
    std::fs::write(&file, vec![0u8; 2048]).unwrap();
    let err = validate_file_size(&file, 1024, "max_file_bytes").unwrap_err();
    assert!(err.to_string().contains("max_file_bytes"), "err = {err}");
}

#[test]
fn pdf_extract_permit_rejects_parallel_dispatch() {
    let sem = Arc::new(Semaphore::new(1));
    let first = try_acquire_extract_permit_from(&sem).expect("first permit should succeed");
    let err = try_acquire_extract_permit_from(&sem).unwrap_err();
    assert!(
        err.to_string().contains("already in progress"),
        "err = {err}"
    );
    drop(first);
    assert!(
        try_acquire_extract_permit_from(&sem).is_ok(),
        "permit should be acquirable after release"
    );
}

#[test]
fn sweep_idle_pdf_extract_semaphores_prunes_only_idle_entries() {
    let mut map: HashMap<PathBuf, Arc<Semaphore>> = HashMap::new();
    let idle = Arc::new(Semaphore::new(PDF_EXTRACT_CONCURRENCY_LIMIT));
    let busy = Arc::new(Semaphore::new(PDF_EXTRACT_CONCURRENCY_LIMIT));
    let in_use = Arc::new(Semaphore::new(PDF_EXTRACT_CONCURRENCY_LIMIT));

    let _busy_permit = busy.clone().try_acquire_owned().unwrap();
    let _in_use_ref = in_use.clone();

    map.insert(PathBuf::from("/tmp/digest-idle.pdf"), idle);
    map.insert(PathBuf::from("/tmp/digest-busy.pdf"), busy.clone());
    map.insert(PathBuf::from("/tmp/digest-in-use.pdf"), in_use.clone());

    let removed = sweep_idle_pdf_extract_semaphores(&mut map);
    assert_eq!(removed, 1, "removed = {removed}");
    assert!(!map.contains_key(&PathBuf::from("/tmp/digest-idle.pdf")));
    assert!(map.contains_key(&PathBuf::from("/tmp/digest-busy.pdf")));
    assert!(map.contains_key(&PathBuf::from("/tmp/digest-in-use.pdf")));
}

#[test]
fn get_or_insert_pdf_extract_semaphore_sweeps_idle_on_soft_limit() {
    let mut map: HashMap<PathBuf, Arc<Semaphore>> = HashMap::new();
    let idle = Arc::new(Semaphore::new(PDF_EXTRACT_CONCURRENCY_LIMIT));
    let busy = Arc::new(Semaphore::new(PDF_EXTRACT_CONCURRENCY_LIMIT));
    let _busy_permit = busy.clone().try_acquire_owned().unwrap();

    let idle_path = PathBuf::from("/tmp/digest-soft-idle.pdf");
    let busy_path = PathBuf::from("/tmp/digest-soft-busy.pdf");
    let new_path = PathBuf::from("/tmp/digest-soft-new.pdf");
    map.insert(idle_path.clone(), idle);
    map.insert(busy_path.clone(), busy.clone());

    let inserted = get_or_insert_pdf_extract_semaphore(&mut map, &new_path, 1, 16)
        .expect("insert should succeed after idle sweep");
    assert_eq!(inserted.available_permits(), PDF_EXTRACT_CONCURRENCY_LIMIT);
    assert!(!map.contains_key(&idle_path), "idle entry should be swept");
    assert!(
        map.contains_key(&busy_path),
        "busy entry should be retained"
    );
    assert!(map.contains_key(&new_path), "new entry should be inserted");
}

#[test]
fn get_or_insert_pdf_extract_semaphore_rejects_when_hard_limit_reached() {
    let mut map: HashMap<PathBuf, Arc<Semaphore>> = HashMap::new();
    let busy_a = Arc::new(Semaphore::new(PDF_EXTRACT_CONCURRENCY_LIMIT));
    let busy_b = Arc::new(Semaphore::new(PDF_EXTRACT_CONCURRENCY_LIMIT));
    let _busy_a_permit = busy_a.clone().try_acquire_owned().unwrap();
    let _busy_b_permit = busy_b.clone().try_acquire_owned().unwrap();

    map.insert(PathBuf::from("/tmp/digest-hard-a.pdf"), busy_a);
    map.insert(PathBuf::from("/tmp/digest-hard-b.pdf"), busy_b);
    let err =
        get_or_insert_pdf_extract_semaphore(&mut map, Path::new("/tmp/digest-hard-new.pdf"), 1, 2)
            .unwrap_err();
    assert!(
        err.to_string().contains("cache limit reached"),
        "err = {err}"
    );
}

#[tokio::test]
async fn run_blocking_with_timeout_reports_timeout() {
    let err = run_blocking_with_timeout(0, "slow test task", || {
        std::thread::sleep(std::time::Duration::from_millis(20));
        Ok::<_, AppError>(())
    })
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("slow test task timed out"),
        "err = {err}"
    );
}

#[tokio::test]
async fn extract_pdf_async_timeout_blocks_same_source_until_worker_exits() {
    struct DelayReset(u64);
    impl Drop for DelayReset {
        fn drop(&mut self) {
            let _ = set_pdf_extract_test_delay_ms(self.0);
        }
    }

    let previous = set_pdf_extract_test_delay_ms(1_500);
    let _reset = DelayReset(previous);

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("slow.pdf");
    // Content validity is not important here; the test exercises timeout/gate behavior.
    std::fs::write(&file, b"%PDF-1.4\n%test\n").unwrap();

    let first = extract_pdf_async(&file, &file, 1, 1).await.unwrap_err();
    assert!(first.to_string().contains("timed out"), "err = {first}");

    let second = extract_pdf_async(&file, &file, 1, 1).await.unwrap_err();
    assert!(
        second.to_string().contains("already in progress"),
        "err = {second}"
    );

    // After the delayed worker exits, gate contention for this source should clear.
    tokio::time::sleep(Duration::from_millis(700)).await;
    match extract_pdf_async(&file, &file, 1, 1).await {
        Ok(_) => {}
        Err(err) => assert!(
            !err.to_string().contains("already in progress"),
            "unexpected persistent gate contention: {err}"
        ),
    }
}

#[tokio::test]
async fn snapshot_audio_file_is_stable_after_source_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("stable.mp3");
    let original = b"first-version-bytes".to_vec();
    std::fs::write(&source, &original).unwrap();

    let snapshot = snapshot_audio_file_async(&source, 10_000).await.unwrap();

    std::fs::write(&source, b"second-version-bytes").unwrap();
    let snap_bytes = std::fs::read(snapshot.path()).unwrap();
    assert_eq!(snap_bytes, original);
}

#[test]
fn truncate_to_max_chars_appends_notice() {
    let result = truncate_to_max_chars("abcdefghij", 5);
    assert!(result.truncated);
    assert!(
        result.content.starts_with("abcde"),
        "content = {}",
        result.content
    );
    assert!(
        result.content.contains("[Truncated:"),
        "content = {}",
        result.content
    );
    assert!(
        result.content.contains("original had 10 characters"),
        "content = {}",
        result.content
    );
    assert_eq!(result.source_word_count, 1);
    assert!(result.returned_word_count.is_some());
}

#[test]
fn retry_after_delay_parses_seconds_header() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::RETRY_AFTER,
        reqwest::header::HeaderValue::from_static("7"),
    );
    let delay = retry_after_delay(&headers).expect("retry-after should parse");
    assert_eq!(delay, std::time::Duration::from_secs(7));
}

#[test]
fn retry_after_delay_parses_http_date_header() {
    let now = SystemTime::now();
    let at = now + Duration::from_secs(5);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::RETRY_AFTER,
        reqwest::header::HeaderValue::from_str(&httpdate::fmt_http_date(at)).unwrap(),
    );
    let delay = retry_after_delay(&headers).expect("retry-after date should parse");
    assert!(delay <= Duration::from_secs(5), "delay = {delay:?}");
}

#[test]
fn retry_after_delay_past_http_date_returns_zero() {
    let past = SystemTime::now() - Duration::from_secs(60);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::RETRY_AFTER,
        reqwest::header::HeaderValue::from_str(&httpdate::fmt_http_date(past)).unwrap(),
    );
    let delay = retry_after_delay(&headers).expect("retry-after date should parse");
    assert_eq!(delay, Duration::from_secs(0));
}

#[test]
fn resolve_openai_api_key_missing() {
    let err = resolve_openai_api_key_with(|_| Err(VarError::NotPresent)).unwrap_err();
    assert!(err.to_string().contains("OPENAI_API_KEY"), "err = {err}");
}

#[test]
fn resolve_openai_api_key_empty_rejected() {
    let err = resolve_openai_api_key_with(|_| Ok("   ".to_string())).unwrap_err();
    assert!(err.to_string().contains("is empty"), "err = {err}");
}

#[tokio::test]
async fn digest_url_output_includes_fetch_metadata() {
    let app = axum::Router::new().route(
        "/doc",
        axum::routing::get(|| async move {
            (
                [("content-type", "text/html")],
                "<html><body><main>Hello world.</main></body></html>",
            )
        }),
    );
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping test: loopback bind is not permitted in this environment");
            return;
        }
        Err(e) => panic!("failed to bind local test listener: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let fw_cfg = encmind_core::config::EgressFirewallConfig {
        enabled: false,
        ..Default::default()
    };
    let runtime = Arc::new(RwLock::new(RuntimeResources {
        llm_backend: Some(Arc::new(StubLlmBackend {
            response: "stub summary".to_string(),
        })),
        tool_registry: Arc::new(ToolRegistry::new()),
    }));
    let handler = DigestUrlHandler {
        config: DigestConfig::default(),
        firewall: Arc::new(EgressFirewall::new(&fw_cfg)),
        runtime,
    };

    let output = handler
        .handle(
            json!({ "url": format!("http://{addr}/doc"), "length": "short" }),
            &SessionId::from_string("s"),
            &AgentId::new("main"),
        )
        .await
        .expect("digest_url should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&output).expect("valid JSON output");

    assert_eq!(parsed["summary"], "stub summary");
    assert_eq!(parsed["fetch"]["final_url"], format!("http://{addr}/doc"));
    assert!(parsed["fetch"]["title"].is_null());
    assert!(parsed["fetch"]["truncated"].is_boolean());
    assert!(parsed["fetch"]["byte_length"].is_u64());
    assert_eq!(parsed["fetch"]["content_type"], "text/html");
    server.abort();
}

#[tokio::test]
async fn register_skips_file_tools_when_disabled() {
    let fw_cfg = encmind_core::config::EgressFirewallConfig {
        enabled: false,
        ..Default::default()
    };
    let runtime = Arc::new(RwLock::new(RuntimeResources {
        llm_backend: Some(Arc::new(StubLlmBackend {
            response: "stub summary".to_string(),
        })),
        tool_registry: Arc::new(ToolRegistry::new()),
    }));
    let plugin = DigestPlugin::new(
        DigestConfig {
            enable_file_tools: false,
            ..Default::default()
        },
        Arc::new(EgressFirewall::new(&fw_cfg)),
        runtime,
    );

    let mut registrar = RecordingRegistrar::new("digest");
    plugin
        .register(&mut registrar)
        .await
        .expect("registration should succeed");

    assert!(registrar.tools.contains(&"summarize".to_string()));
    assert!(registrar.tools.contains(&"url".to_string()));
    assert!(!registrar.tools.contains(&"file".to_string()));
    assert!(!registrar.tools.contains(&"transcribe".to_string()));
}

#[tokio::test]
async fn register_includes_file_tools_when_enabled() {
    let file_root =
        tempfile::tempdir().expect("failed to create temporary directory for file_root config");
    let fw_cfg = encmind_core::config::EgressFirewallConfig {
        enabled: false,
        ..Default::default()
    };
    let runtime = Arc::new(RwLock::new(RuntimeResources {
        llm_backend: Some(Arc::new(StubLlmBackend {
            response: "stub summary".to_string(),
        })),
        tool_registry: Arc::new(ToolRegistry::new()),
    }));
    let plugin = DigestPlugin::new(
        DigestConfig {
            enable_file_tools: true,
            file_root: Some(file_root.path().to_path_buf()),
            ..Default::default()
        },
        Arc::new(EgressFirewall::new(&fw_cfg)),
        runtime,
    );

    let mut registrar = RecordingRegistrar::new("digest");
    plugin
        .register(&mut registrar)
        .await
        .expect("registration should succeed");

    assert!(registrar.tools.contains(&"summarize".to_string()));
    assert!(registrar.tools.contains(&"url".to_string()));
    assert!(registrar.tools.contains(&"file".to_string()));
    assert!(registrar.tools.contains(&"transcribe".to_string()));
}

#[tokio::test]
async fn register_skips_llm_tools_when_backend_missing() {
    let file_root =
        tempfile::tempdir().expect("failed to create temporary directory for file_root config");
    let fw_cfg = encmind_core::config::EgressFirewallConfig {
        enabled: false,
        ..Default::default()
    };
    let runtime = Arc::new(RwLock::new(RuntimeResources {
        llm_backend: None,
        tool_registry: Arc::new(ToolRegistry::new()),
    }));
    let plugin = DigestPlugin::new(
        DigestConfig {
            enable_file_tools: true,
            file_root: Some(file_root.path().to_path_buf()),
            ..Default::default()
        },
        Arc::new(EgressFirewall::new(&fw_cfg)),
        runtime,
    );

    let mut registrar = RecordingRegistrar::new("digest");
    plugin
        .register(&mut registrar)
        .await
        .expect("registration should succeed");

    assert!(!registrar.tools.contains(&"summarize".to_string()));
    assert!(!registrar.tools.contains(&"url".to_string()));
    assert!(registrar.tools.contains(&"file".to_string()));
    assert!(registrar.tools.contains(&"transcribe".to_string()));
}

#[tokio::test]
async fn register_includes_transcribe_when_whisper_client_missing() {
    let file_root =
        tempfile::tempdir().expect("failed to create temporary directory for file_root config");
    let fw_cfg = encmind_core::config::EgressFirewallConfig {
        enabled: false,
        ..Default::default()
    };
    let runtime = Arc::new(RwLock::new(RuntimeResources {
        llm_backend: Some(Arc::new(StubLlmBackend {
            response: "stub summary".to_string(),
        })),
        tool_registry: Arc::new(ToolRegistry::new()),
    }));
    let plugin = DigestPlugin::new(
        DigestConfig {
            enable_file_tools: true,
            file_root: Some(file_root.path().to_path_buf()),
            ..Default::default()
        },
        Arc::new(EgressFirewall::new(&fw_cfg)),
        runtime,
    );
    *plugin.whisper_client.write().await = None;

    let mut registrar = RecordingRegistrar::new("digest");
    plugin
        .register(&mut registrar)
        .await
        .expect("registration should succeed");

    assert!(registrar.tools.contains(&"transcribe".to_string()));
}

#[tokio::test]
async fn whisper_client_invalid_user_agent_still_keeps_redirects_disabled() {
    let app = axum::Router::new()
        .route(
            "/start",
            axum::routing::get(|| async move {
                axum::http::Response::builder()
                    .status(axum::http::StatusCode::FOUND)
                    .header(axum::http::header::LOCATION, "/final")
                    .body(axum::body::Body::empty())
                    .expect("failed to build redirect response")
            }),
        )
        .route("/final", axum::routing::get(|| async move { "ok" }));

    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping test: loopback bind is not permitted in this environment");
            return;
        }
        Err(e) => panic!("failed to bind local test listener: {e}"),
    };
    let addr = listener.local_addr().expect("failed to read local addr");
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Invalid header value forces the primary build path to fail.
    let client = build_whisper_client_with_user_agent(30, "bad\nua")
        .expect("fallback builder should still produce a hardened client");
    let resp = client
        .get(format!("http://{addr}/start"))
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FOUND,
        "client should not auto-follow redirects"
    );

    server.abort();
}

#[tokio::test]
async fn snapshot_audio_file_without_extension_keeps_no_extension() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("clip");
    std::fs::write(&source, b"audio-bytes").unwrap();

    let snapshot = snapshot_audio_file_async(&source, 10_000).await.unwrap();
    assert!(
        snapshot.path().extension().is_none(),
        "snapshot path should not gain a synthetic extension: {}",
        snapshot.path().display()
    );
}

#[tokio::test]
async fn whisper_transcribe_reports_error_for_non_success_response() {
    let app = axum::Router::new().route(
        "/v1/audio/transcriptions",
        axum::routing::post(|| async move {
            (
                axum::http::StatusCode::BAD_REQUEST,
                "invalid request payload",
            )
        }),
    );
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping test: loopback bind is not permitted in this environment");
            return;
        }
        Err(e) => panic!("failed to bind local test listener: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let audio_path = dir.path().join("test.mp3");
    std::fs::write(&audio_path, vec![1_u8, 2_u8, 3_u8]).unwrap();
    let fw_cfg = encmind_core::config::EgressFirewallConfig {
        enabled: false,
        ..Default::default()
    };
    let firewall = EgressFirewall::new(&fw_cfg);
    let url = format!("http://{addr}/v1/audio/transcriptions");
    let request = WhisperTranscribeRequest {
        api_key: "test-key",
        file_path: &audio_path,
        filename: "test.mp3",
        model: "whisper-1",
        language: None,
        url: &url,
    };
    let err = whisper_transcribe(&firewall, 180, &request)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("400") && err.to_string().contains("upstream request failed"),
        "err = {err}"
    );
    server.abort();
}

#[tokio::test]
async fn whisper_transcribe_retries_429_with_retry_after_then_succeeds() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_handler = attempts.clone();
    let app = axum::Router::new().route(
        "/v1/audio/transcriptions",
        axum::routing::post(move || {
            let attempts = attempts_handler.clone();
            async move {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    axum::http::Response::builder()
                        .status(axum::http::StatusCode::TOO_MANY_REQUESTS)
                        .header(axum::http::header::RETRY_AFTER, "0")
                        .body(axum::body::Body::from("rate limited"))
                        .expect("failed to build retry response")
                } else {
                    axum::http::Response::builder()
                        .status(axum::http::StatusCode::OK)
                        .body(axum::body::Body::from("transcript ok"))
                        .expect("failed to build success response")
                }
            }
        }),
    );
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping test: loopback bind is not permitted in this environment");
            return;
        }
        Err(e) => panic!("failed to bind local test listener: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let audio_path = dir.path().join("test.mp3");
    std::fs::write(&audio_path, vec![1_u8, 2_u8, 3_u8]).unwrap();
    let fw_cfg = encmind_core::config::EgressFirewallConfig {
        enabled: false,
        ..Default::default()
    };
    let firewall = EgressFirewall::new(&fw_cfg);
    let url = format!("http://{addr}/v1/audio/transcriptions");
    let request = WhisperTranscribeRequest {
        api_key: "test-key",
        file_path: &audio_path,
        filename: "test.mp3",
        model: "whisper-1",
        language: None,
        url: &url,
    };
    let transcript = whisper_transcribe(&firewall, 180, &request)
        .await
        .expect("whisper should eventually succeed");
    assert_eq!(transcript, "transcript ok");
    assert!(
        attempts.load(Ordering::SeqCst) >= 2,
        "expected at least one retry"
    );
    server.abort();
}

#[tokio::test]
async fn read_text_file_capped_async_reports_lossy_decoding() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("latin1.txt");
    // Invalid UTF-8 sequence: 0xFF
    std::fs::write(&file, vec![b'a', b'b', 0xFF, b'c']).unwrap();
    let (text, lossy, replacement_count) =
        read_text_file_capped_async(&file, 10_000).await.unwrap();
    assert!(lossy, "expected lossy decode flag");
    assert_eq!(text, "ab?c");
    assert_eq!(replacement_count, 1);
}

#[tokio::test]
async fn read_text_file_capped_async_lossy_decode_does_not_expand_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("invalid.bin");
    let input = vec![0xFF_u8; 4096];
    std::fs::write(&file, &input).unwrap();
    let (text, lossy, replacement_count) = read_text_file_capped_async(&file, input.len())
        .await
        .unwrap();
    assert!(lossy, "expected lossy decode flag");
    assert_eq!(replacement_count, input.len());
    assert!(
        text.len() <= input.len(),
        "decoded output should not exceed input bytes: {} > {}",
        text.len(),
        input.len()
    );
}

#[tokio::test]
async fn read_text_file_capped_async_rejects_oversize() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("big.txt");
    std::fs::write(&file, vec![b'x'; 2_048]).unwrap();
    let err = read_text_file_capped_async(&file, 1_024).await.unwrap_err();
    assert!(err.to_string().contains("max_file_bytes"), "err = {err}");
}

#[tokio::test]
async fn snapshot_audio_file_async_rejects_oversize() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("clip.mp3");
    std::fs::write(&source, vec![0_u8; 2_048]).unwrap();
    let err = snapshot_audio_file_async(&source, 1_024).await.unwrap_err();
    assert!(err.to_string().contains("max_audio_bytes"), "err = {err}");
}

#[tokio::test]
async fn digest_file_output_contract_includes_lossy_and_optional_returned_word_count() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("sample.txt");
    // Invalid UTF-8 plus enough words to trigger truncation.
    std::fs::write(
        &file,
        vec![
            b'a', b'l', b'p', b'h', b'a', b' ', b'b', b'e', b't', b'a', b' ', 0xFF, b' ', b'g',
            b'a', b'm', b'm', b'a',
        ],
    )
    .unwrap();

    let handler = DigestFileHandler {
        config: DigestConfig {
            file_root: Some(dir.path().to_path_buf()),
            max_extracted_chars: 10,
            ..Default::default()
        },
        canonical_file_root: Some(dir.path().canonicalize().unwrap()),
    };
    let output = handler
        .handle(
            json!({ "path": file.display().to_string() }),
            &SessionId::from_string("s"),
            &AgentId::new("main"),
        )
        .await
        .expect("digest_file should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&output).expect("valid JSON output");

    assert!(parsed["encoding_lossy"].as_bool().unwrap_or(false));
    assert!(parsed["encoding_replacement_count"].is_u64());
    assert!(
        parsed["encoding_replacement_count"]
            .as_u64()
            .is_some_and(|n| n > 0),
        "expected replacements for invalid UTF-8 input"
    );
    assert!(parsed["truncated"].as_bool().unwrap_or(false));
    assert_eq!(parsed["word_count_scope"], "source_excerpt_pre_note");
    assert!(parsed.get("returned_word_count").is_some());
    assert!(parsed.get("source_total_word_count").is_some());
    assert!(parsed["word_count"].is_u64());
    assert!(parsed["returned_word_count"].is_u64());
}

#[tokio::test]
async fn digest_file_non_truncated_omits_returned_word_count() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("plain.txt");
    std::fs::write(&file, "alpha beta gamma").unwrap();

    let handler = DigestFileHandler {
        config: DigestConfig {
            file_root: Some(dir.path().to_path_buf()),
            max_extracted_chars: 10_000,
            ..Default::default()
        },
        canonical_file_root: Some(dir.path().canonicalize().unwrap()),
    };
    let output = handler
        .handle(
            json!({ "path": file.display().to_string() }),
            &SessionId::from_string("s"),
            &AgentId::new("main"),
        )
        .await
        .expect("digest_file should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&output).expect("valid JSON output");

    assert!(!parsed["truncated"].as_bool().unwrap_or(true));
    assert_eq!(parsed["word_count"], 3);
    assert!(!parsed["encoding_lossy"].as_bool().unwrap_or(true));
    assert_eq!(parsed["encoding_replacement_count"].as_u64(), Some(0));
    assert!(parsed.get("returned_word_count").is_none());
    assert!(parsed.get("source_total_word_count").is_none());
}

#[tokio::test]
async fn digest_file_pdf_uses_pdf_cap_label_when_oversized() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("oversized.pdf");
    std::fs::write(&file, vec![0_u8; 2_048]).unwrap();

    let handler = DigestFileHandler {
        config: DigestConfig {
            file_root: Some(dir.path().to_path_buf()),
            max_file_bytes: 8_192,
            max_pdf_file_bytes: 1_024,
            ..Default::default()
        },
        canonical_file_root: Some(dir.path().canonicalize().unwrap()),
    };
    let err = handler
        .handle(
            json!({ "path": file.display().to_string() }),
            &SessionId::from_string("s"),
            &AgentId::new("main"),
        )
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("max_pdf_file_bytes"),
        "err = {err}"
    );
}

#[test]
fn truncate_to_max_chars_reports_source_and_returned_word_counts() {
    let result = truncate_to_max_chars("alpha beta gamma delta epsilon zeta", 11);
    // "alpha beta " (2 words) + truncation note in returned payload.
    assert!(result.truncated);
    assert_eq!(result.source_word_count, 2);
    let returned = result
        .returned_word_count
        .expect("returned_word_count should be set when truncated");
    assert!(returned > result.source_word_count);
}

// ── Integration tests (require external services) ─────────────

#[tokio::test]
#[ignore]
async fn transcribe_integration() {
    // Requires OPENAI_API_KEY and a short audio file at /tmp/test_audio.mp3
    let api_key = std::env::var("OPENAI_API_KEY").expect("OPENAI_API_KEY must be set");
    let fw_cfg = encmind_core::config::EgressFirewallConfig {
        enabled: false,
        ..Default::default()
    };
    let firewall = EgressFirewall::new(&fw_cfg);
    let request = WhisperTranscribeRequest {
        api_key: &api_key,
        file_path: Path::new("/tmp/test_audio.mp3"),
        filename: "test_audio.mp3",
        model: "whisper-1",
        language: Some("en"),
        url: OPENAI_WHISPER_TRANSCRIBE_URL,
    };
    let result = whisper_transcribe(&firewall, 180, &request).await;
    assert!(result.is_ok(), "transcription failed: {:?}", result.err());
    assert!(!result.unwrap().is_empty());
}

#[test]
#[ignore]
fn pdf_integration() {
    // Requires a real PDF at /tmp/test.pdf
    let path = Path::new("/tmp/test.pdf");
    let (content, pages) = extract_pdf(path, 10).unwrap();
    assert!(!content.is_empty(), "PDF extraction should produce text");
    assert!(pages > 0, "should have at least one page");
    assert!(
        content.contains("--- Page 1 ---"),
        "should have page markers"
    );
}

// ── List files tests ─────────────────────────────────────────────

#[test]
fn list_dir_entries_returns_sorted_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("charlie.txt"), "c").unwrap();
    std::fs::write(dir.path().join("alpha.txt"), "a").unwrap();
    std::fs::write(dir.path().join("bravo.pdf"), "b").unwrap();
    std::fs::create_dir(dir.path().join("subdir")).unwrap();

    let listed = list_dir_entries(dir.path(), None, 100).unwrap();
    assert!(!listed.truncated);
    assert_eq!(listed.total_entries, 4);
    assert_eq!(listed.matched_entries, 4);
    assert_eq!(listed.entries.len(), 4);
    assert_eq!(listed.entries[0].name, "alpha.txt");
    assert_eq!(listed.entries[0].entry_type, "file");
    assert!(listed.entries[0].size_bytes.is_some());
    assert_eq!(listed.entries[1].name, "bravo.pdf");
    assert_eq!(listed.entries[2].name, "charlie.txt");
    assert_eq!(listed.entries[3].name, "subdir");
    assert_eq!(listed.entries[3].entry_type, "directory");
    assert!(listed.entries[3].size_bytes.is_none());
}

#[test]
fn list_dir_entries_truncates_at_max() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..10 {
        std::fs::write(dir.path().join(format!("file_{i:02}.txt")), "x").unwrap();
    }
    let listed = list_dir_entries(dir.path(), None, 3).unwrap();
    assert_eq!(listed.total_entries, 10);
    assert_eq!(listed.matched_entries, 10);
    assert_eq!(listed.entries.len(), 3);
    assert!(listed.truncated);
}

#[test]
fn list_dir_entries_applies_filter_before_truncation() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..20 {
        std::fs::write(dir.path().join(format!("noise_{i:02}.txt")), "x").unwrap();
    }
    std::fs::write(dir.path().join("target-report.pdf"), "pdf").unwrap();

    let listed = list_dir_entries(dir.path(), Some("target"), 1).unwrap();
    assert_eq!(listed.total_entries, 21);
    assert_eq!(listed.matched_entries, 1);
    assert_eq!(listed.entries.len(), 1);
    assert_eq!(listed.entries[0].name, "target-report.pdf");
    assert!(!listed.truncated);
}

#[test]
fn validate_dir_path_rejects_outside_root() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let err = validate_dir_path(outside.path().to_str().unwrap(), root.path()).unwrap_err();
    assert!(
        err.to_string().contains("outside the allowed file_root"),
        "err = {err}"
    );
}

#[test]
fn validate_dir_path_rejects_file_as_dir() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("not_a_dir.txt");
    std::fs::write(&file, "x").unwrap();
    let err = validate_dir_path(file.to_str().unwrap(), dir.path()).unwrap_err();
    assert!(
        err.to_string().contains("is not a directory"),
        "err = {err}"
    );
}

#[test]
fn validate_dir_path_rejects_relative() {
    let dir = tempfile::tempdir().unwrap();
    let err = validate_dir_path("relative/path", dir.path()).unwrap_err();
    assert!(err.to_string().contains("must be absolute"), "err = {err}");
}

#[tokio::test]
async fn digest_list_files_handler_lists_and_filters() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("report.pdf"), "pdf").unwrap();
    std::fs::write(dir.path().join("notes.txt"), "txt").unwrap();
    std::fs::write(dir.path().join("data.csv"), "csv").unwrap();

    let handler = DigestListFilesHandler {
        config: DigestConfig {
            max_list_entries: 100,
            ..Default::default()
        },
        canonical_file_root: dir.path().canonicalize().unwrap(),
    };

    // List all files (no directory, no filter)
    let output = handler
        .handle(
            json!({}),
            &SessionId::from_string("s"),
            &AgentId::new("main"),
        )
        .await
        .expect("list should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed["total_entries"], 3);
    assert_eq!(parsed["matched_entries"], 3);
    assert_eq!(parsed["shown_entries"], 3);
    assert!(!parsed["truncated"].as_bool().unwrap());

    // Filter by substring
    let output = handler
        .handle(
            json!({"filter": "pdf"}),
            &SessionId::from_string("s"),
            &AgentId::new("main"),
        )
        .await
        .expect("filtered list should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed["shown_entries"], 1);
    assert_eq!(parsed["matched_entries"], 1);
    assert_eq!(parsed["total_entries"], 3);
}

#[tokio::test]
async fn digest_list_files_handler_reports_total_entries_when_capped() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "a").unwrap();
    std::fs::write(dir.path().join("b.txt"), "b").unwrap();
    std::fs::write(dir.path().join("c.txt"), "c").unwrap();

    let handler = DigestListFilesHandler {
        config: DigestConfig {
            max_list_entries: 1,
            ..Default::default()
        },
        canonical_file_root: dir.path().canonicalize().unwrap(),
    };

    let output = handler
        .handle(
            json!({}),
            &SessionId::from_string("s"),
            &AgentId::new("main"),
        )
        .await
        .expect("list should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed["total_entries"], 3);
    assert_eq!(parsed["matched_entries"], 3);
    assert_eq!(parsed["shown_entries"], 1);
    assert!(parsed["truncated"].as_bool().unwrap());
}

#[tokio::test]
async fn digest_list_files_handler_defaults_to_file_root() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "a").unwrap();

    let handler = DigestListFilesHandler {
        config: DigestConfig {
            max_list_entries: 100,
            ..Default::default()
        },
        canonical_file_root: dir.path().canonicalize().unwrap(),
    };

    let output = handler
        .handle(
            json!({}),
            &SessionId::from_string("s"),
            &AgentId::new("main"),
        )
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed["directory"].as_str().unwrap(), ".");
    assert_eq!(parsed["total_entries"], 1);
}

#[tokio::test]
async fn digest_list_files_handler_rejects_outside_root() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();

    let handler = DigestListFilesHandler {
        config: DigestConfig {
            max_list_entries: 100,
            ..Default::default()
        },
        canonical_file_root: root.path().canonicalize().unwrap(),
    };

    let err = handler
        .handle(
            json!({"directory": outside.path().display().to_string()}),
            &SessionId::from_string("s"),
            &AgentId::new("main"),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("outside the allowed file_root"),
        "err = {err}"
    );
}
