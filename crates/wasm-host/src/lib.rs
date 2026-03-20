pub mod abi;
pub mod hook_bridge;
pub mod host_functions;
pub mod invoker;
pub mod limiter;
pub mod manifest;
pub mod secret_scanner;
pub mod skill_loader;

mod runtime;
pub use runtime::{
    build_linker, ApprovalPrompter, ExecutionContext, OutboundPolicy, StoreState, WasmRuntime,
};

pub use abi::SkillAbi;

/// Re-export the SQLite pool type for StoreState dependency.
pub type SqlitePool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
