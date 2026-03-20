//! Host functions exposed to WASM skill modules.

pub mod approval;
pub mod capability;
pub mod config;
pub mod context;
pub mod hooks;
pub mod kv;
pub mod log;
pub mod net;

// Re-export capability checks for backward compatibility
pub use capability::{check_env_access, check_fs_read, check_fs_write, check_net_outbound};

use encmind_core::error::WasmHostError;
use wasmtime::Linker;

use crate::runtime::StoreState;

/// Register all host functions on a Linker.
pub fn register_all(linker: &mut Linker<StoreState>) -> Result<(), WasmHostError> {
    config::register(linker)?;
    context::register(linker)?;
    log::register(linker)?;
    kv::register(linker)?;
    net::register(linker)?;
    hooks::register(linker)?;
    approval::register(linker)?;
    Ok(())
}
