use thiserror::Error;

/// Root error type wrapping all sub-crate errors at the agent boundary.
#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error(transparent)]
    Llm(#[from] LlmError),

    #[error(transparent)]
    Tee(#[from] TeeError),

    #[error(transparent)]
    WasmHost(#[from] WasmHostError),

    #[error(transparent)]
    Channel(#[from] ChannelError),

    #[error(transparent)]
    Mcp(#[from] McpError),

    #[error(transparent)]
    Gateway(#[from] GatewayError),

    #[error(transparent)]
    Memory(#[from] MemoryError),

    #[error(transparent)]
    Plugin(#[from] PluginError),

    #[error("tool denied ({reason}): {message}")]
    ToolDenied { reason: String, message: String },

    #[error("{0}")]
    Internal(String),
}

/// Storage layer errors.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SQLite error: {0}")]
    Sqlite(String),

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("migration failed: {0}")]
    MigrationFailed(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid data: {0}")]
    InvalidData(String),

    #[error("environment variable error: {0}")]
    EnvVar(#[from] std::env::VarError),

    #[error("not supported: {0}")]
    NotSupported(String),

    #[error("validation failed: {0}")]
    ValidationFailed(String),
}

/// TEE-related errors.
#[derive(Debug, Error)]
pub enum TeeError {
    #[error("TEE not available on this platform")]
    NotAvailable,

    #[error("attestation failed: {0}")]
    AttestationFailed(String),

    #[error("key sealing failed: {0}")]
    SealFailed(String),

    #[error("key unsealing failed: {0}")]
    UnsealFailed(String),

    #[error("TEE I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// LLM inference errors.
#[derive(Debug, Error)]
pub enum LlmError {
    #[error("LLM not configured")]
    NotConfigured,

    #[error("inference error: {0}")]
    InferenceError(String),

    #[error("tokenization error: {0}")]
    TokenizationError(String),

    #[error("provider error: {0}")]
    ProviderError(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("stream error: {0}")]
    StreamError(String),

    #[error("all providers unhealthy")]
    AllProvidersUnhealthy,

    #[error("request cancelled")]
    Cancelled,

    #[error("rate limited")]
    RateLimited { retry_after_secs: Option<u64> },
}

/// WASM host errors.
#[derive(Debug, Error)]
pub enum WasmHostError {
    #[error("module load failed: {0}")]
    ModuleLoadFailed(String),

    #[error("execution failed: {0}")]
    ExecutionFailed(String),

    #[error("capability denied: {0}")]
    CapabilityDenied(String),

    #[error("manifest parse error: {0}")]
    ManifestParseError(String),

    #[error("resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    #[error("secret detected in output: {0}")]
    SecretDetected(String),

    #[error("host function error: {0}")]
    HostFunctionError(String),
}

/// Channel adapter errors
#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("channel not configured: {0}")]
    NotConfigured(String),

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("send failed: {0}")]
    SendFailed(String),

    #[error("receive failed: {0}")]
    ReceiveFailed(String),

    #[error("access denied: {0}")]
    AccessDenied(String),

    #[error("account not found: {0}")]
    AccountNotFound(String),

    #[error("login failed: {0}")]
    LoginFailed(String),

    #[error("logout failed: {0}")]
    LogoutFailed(String),

    #[error("credential failed: {0}")]
    CredentialFailed(String),

    #[error("probe failed: {0}")]
    ProbeFailed(String),
}

/// Gateway errors
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("protocol error: {0}")]
    ProtocolError(String),

    #[error("rate limited")]
    RateLimited,

    #[error("lockdown active")]
    LockdownActive,

    #[error("device not paired: {0}")]
    DeviceNotPaired(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),
}

/// Memory / RAG errors
#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("embedding failed: {0}")]
    EmbeddingFailed(String),

    #[error("vector store error: {0}")]
    VectorStoreError(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("model not loaded: {0}")]
    ModelNotLoaded(String),

    #[error("quality gate failed: {0}")]
    QualityGateFailed(String),

    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

/// Plugin lifecycle errors
#[derive(Debug, Error)]
pub enum PluginError {
    #[error("registration failed: {0}")]
    RegistrationFailed(String),

    #[error("plugin not found: {0}")]
    NotFound(String),

    #[error("hook execution failed: {0}")]
    HookFailed(String),

    #[error("method handler error: {0}")]
    MethodError(String),

    #[error("shutdown failed: {0}")]
    ShutdownFailed(String),

    #[error("policy denied: {0}")]
    PolicyDenied(String),
}

/// MCP client errors
#[derive(Debug, Error)]
pub enum McpError {
    #[error("MCP server not configured: {0}")]
    NotConfigured(String),

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("tool call failed: {0}")]
    ToolCallFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_error_display() {
        let err = GatewayError::AuthFailed("bad token".into());
        assert_eq!(err.to_string(), "authentication failed: bad token");
    }

    #[test]
    fn gateway_error_into_app_error() {
        let err = GatewayError::LockdownActive;
        let app_err: AppError = err.into();
        assert!(matches!(app_err, AppError::Gateway(_)));
    }

    #[test]
    fn memory_error_display() {
        let err = MemoryError::EmbeddingFailed("model unavailable".into());
        assert_eq!(err.to_string(), "embedding failed: model unavailable");
    }

    #[test]
    fn memory_error_into_app_error() {
        let err = MemoryError::VectorStoreError("connection lost".into());
        let app_err: AppError = err.into();
        assert!(matches!(app_err, AppError::Memory(_)));
    }

    #[test]
    fn plugin_error_policy_denied_display() {
        let err = PluginError::PolicyDenied("exec_shell not allowed".into());
        assert_eq!(err.to_string(), "policy denied: exec_shell not allowed");
        let app_err: AppError = err.into();
        assert!(matches!(app_err, AppError::Plugin(_)));
    }

    #[test]
    fn gateway_error_variants() {
        let _ = GatewayError::RateLimited;
        let _ = GatewayError::DeviceNotPaired("dev-1".into());
        let _ = GatewayError::PermissionDenied("bash".into());
        let _ = GatewayError::ProtocolError("bad frame".into());
    }

    #[test]
    fn channel_error_new_variants_display() {
        let err = ChannelError::AccountNotFound("acct-1".into());
        assert_eq!(err.to_string(), "account not found: acct-1");

        let err = ChannelError::LoginFailed("bad token".into());
        assert_eq!(err.to_string(), "login failed: bad token");

        let err = ChannelError::LogoutFailed("adapter stop failed".into());
        assert_eq!(err.to_string(), "logout failed: adapter stop failed");

        let err = ChannelError::CredentialFailed("encryption error".into());
        assert_eq!(err.to_string(), "credential failed: encryption error");

        let err = ChannelError::ProbeFailed("timeout".into());
        assert_eq!(err.to_string(), "probe failed: timeout");
    }

    #[test]
    fn channel_error_into_app_error() {
        let err = ChannelError::AccountNotFound("acct-1".into());
        let app_err: AppError = err.into();
        assert!(matches!(app_err, AppError::Channel(_)));
    }
}
