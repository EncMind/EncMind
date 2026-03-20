//! `kv.*` host functions — per-skill key-value persistence.

use encmind_core::error::WasmHostError;
use rusqlite::OptionalExtension;
use wasmtime::{AsContext, AsContextMut, Linker};

use crate::abi;
use crate::runtime::StoreState;

/// Maximum value size: 1 MiB.
pub const MAX_VALUE_SIZE: usize = 1024 * 1024;
/// Maximum key length: 256 bytes printable ASCII.
pub const MAX_KEY_LEN: usize = 256;

/// Register kv host functions on the linker.
pub fn register(linker: &mut Linker<StoreState>) -> Result<(), WasmHostError> {
    // __encmind_kv_get(key_ptr, key_len) -> i64
    linker
        .func_wrap_async(
            "encmind",
            "__encmind_kv_get",
            |mut caller: wasmtime::Caller<'_, StoreState>, (key_ptr, key_len): (i32, i32)| {
                Box::new(async move {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => {
                            caller.data_mut().last_error = Some("no memory export".into());
                            return 0i64;
                        }
                    };

                    let key = match abi::read_guest_string(
                        &memory,
                        caller.as_context(),
                        key_ptr,
                        key_len,
                    ) {
                        Ok(k) => k,
                        Err(e) => {
                            caller.data_mut().last_error = Some(e.to_string());
                            return 0i64;
                        }
                    };

                    if !caller.data().capabilities.kv {
                        caller.data_mut().last_error = Some("kv capability not granted".into());
                        return 0i64;
                    }

                    let db_pool = match caller.data().db_pool.clone() {
                        Some(p) => p,
                        None => {
                            caller.data_mut().last_error = Some("no database available".into());
                            return 0i64;
                        }
                    };

                    let skill_id = caller.data().skill_id.clone();
                    let value: Option<Vec<u8>> = match tokio::task::spawn_blocking(move || {
                        let conn = db_pool.get().map_err(|e| e.to_string())?;
                        conn.query_row(
                            "SELECT value FROM skill_kv WHERE skill_id = ?1 AND key = ?2",
                            rusqlite::params![skill_id, key],
                            |row| row.get::<_, Vec<u8>>(0),
                        )
                        .optional()
                        .map_err(|e| e.to_string())
                    })
                    .await
                    {
                        Ok(Ok(v)) => v,
                        Ok(Err(e)) => {
                            caller.data_mut().last_error = Some(e);
                            return 0i64;
                        }
                        Err(e) => {
                            caller.data_mut().last_error = Some(e.to_string());
                            return 0i64;
                        }
                    };

                    let bytes = match value {
                        Some(v) => v,
                        None => return 0i64,
                    };

                    let alloc_fn = match caller.get_export("__encmind_alloc") {
                        Some(wasmtime::Extern::Func(f)) => match f.typed::<i32, i32>(&caller) {
                            Ok(tf) => tf,
                            Err(e) => {
                                caller.data_mut().last_error = Some(format!("alloc error: {e}"));
                                return 0i64;
                            }
                        },
                        _ => {
                            caller.data_mut().last_error = Some("no __encmind_alloc".into());
                            return 0i64;
                        }
                    };

                    match abi::write_to_guest(&alloc_fn, caller.as_context_mut(), &memory, &bytes)
                        .await
                    {
                        Ok(fat) => fat,
                        Err(e) => {
                            caller.data_mut().last_error = Some(e.to_string());
                            0i64
                        }
                    }
                })
            },
        )
        .map_err(|e| WasmHostError::HostFunctionError(format!("kv.get registration: {e}")))?;

    // __encmind_kv_set(key_ptr, key_len, val_ptr, val_len) -> i32
    linker
        .func_wrap_async(
            "encmind",
            "__encmind_kv_set",
            |mut caller: wasmtime::Caller<'_, StoreState>,
             (key_ptr, key_len, val_ptr, val_len): (i32, i32, i32, i32)| {
                Box::new(async move {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return -1i32,
                    };

                    let key = match abi::read_guest_string(
                        &memory,
                        caller.as_context(),
                        key_ptr,
                        key_len,
                    ) {
                        Ok(k) => k,
                        Err(_) => return -1i32,
                    };

                    if !caller.data().capabilities.kv {
                        caller.data_mut().last_error = Some("kv capability not granted".into());
                        return -1i32;
                    }

                    if key.len() > MAX_KEY_LEN
                        || key.is_empty()
                        || !key.bytes().all(|b| b.is_ascii_graphic())
                    {
                        caller.data_mut().last_error = Some("invalid key".into());
                        return -1i32;
                    }

                    let value =
                        match abi::read_guest_bytes(&memory, caller.as_context(), val_ptr, val_len)
                        {
                            Ok(v) => v,
                            Err(_) => return -1i32,
                        };

                    if value.len() > MAX_VALUE_SIZE {
                        caller.data_mut().last_error = Some(format!(
                            "value too large: {} > {MAX_VALUE_SIZE}",
                            value.len()
                        ));
                        return -1i32;
                    }

                    let db_pool = match caller.data().db_pool.clone() {
                        Some(p) => p,
                        None => return -1i32,
                    };

                    let skill_id = caller.data().skill_id.clone();
                    match tokio::task::spawn_blocking(move || {
                        let conn = db_pool.get().map_err(|e| e.to_string())?;
                        conn.execute(
                            "INSERT OR REPLACE INTO skill_kv (skill_id, key, value, updated_at) \
                             VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
                            rusqlite::params![skill_id, key, value],
                        )
                        .map_err(|e| e.to_string())?;
                        Ok::<_, String>(())
                    })
                    .await
                    {
                        Ok(Ok(())) => 0i32,
                        _ => -1i32,
                    }
                })
            },
        )
        .map_err(|e| WasmHostError::HostFunctionError(format!("kv.set registration: {e}")))?;

    // __encmind_kv_delete(key_ptr, key_len) -> i32
    linker
        .func_wrap_async(
            "encmind",
            "__encmind_kv_delete",
            |mut caller: wasmtime::Caller<'_, StoreState>, (key_ptr, key_len): (i32, i32)| {
                Box::new(async move {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return -1i32,
                    };

                    let key = match abi::read_guest_string(
                        &memory,
                        caller.as_context(),
                        key_ptr,
                        key_len,
                    ) {
                        Ok(k) => k,
                        Err(_) => return -1i32,
                    };

                    if !caller.data().capabilities.kv {
                        return -1i32;
                    }

                    let db_pool = match caller.data().db_pool.clone() {
                        Some(p) => p,
                        None => return -1i32,
                    };

                    let skill_id = caller.data().skill_id.clone();
                    match tokio::task::spawn_blocking(move || {
                        let conn = db_pool.get().map_err(|e| e.to_string())?;
                        conn.execute(
                            "DELETE FROM skill_kv WHERE skill_id = ?1 AND key = ?2",
                            rusqlite::params![skill_id, key],
                        )
                        .map_err(|e| e.to_string())?;
                        Ok::<_, String>(())
                    })
                    .await
                    {
                        Ok(Ok(())) => 0i32,
                        _ => -1i32,
                    }
                })
            },
        )
        .map_err(|e| WasmHostError::HostFunctionError(format!("kv.delete registration: {e}")))?;

    // __encmind_kv_list(prefix_ptr, prefix_len) -> i64
    linker
        .func_wrap_async(
            "encmind",
            "__encmind_kv_list",
            |mut caller: wasmtime::Caller<'_, StoreState>,
             (prefix_ptr, prefix_len): (i32, i32)| {
                Box::new(async move {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => {
                            caller.data_mut().last_error = Some("no memory export".into());
                            return 0i64;
                        }
                    };

                    let prefix =
                        match abi::read_guest_string(&memory, caller.as_context(), prefix_ptr, prefix_len) {
                            Ok(p) => p,
                            Err(e) => {
                                caller.data_mut().last_error = Some(e.to_string());
                                return 0i64;
                            }
                        };

                    if !caller.data().capabilities.kv {
                        caller.data_mut().last_error = Some("kv capability not granted".into());
                        return 0i64;
                    }

                    let db_pool = match caller.data().db_pool.clone() {
                        Some(p) => p,
                        None => {
                            caller.data_mut().last_error = Some("no database".into());
                            return 0i64;
                        }
                    };

                    let skill_id = caller.data().skill_id.clone();
                    let keys: Vec<String> = match tokio::task::spawn_blocking(move || {
                        let conn = db_pool.get().map_err(|e| e.to_string())?;
                        let mut stmt = conn
                            .prepare(
                                "SELECT key FROM skill_kv WHERE skill_id = ?1 AND key LIKE ?2 ORDER BY key",
                            )
                            .map_err(|e| e.to_string())?;
                        let pattern = format!("{prefix}%");
                        let keys: Vec<String> = stmt
                            .query_map(rusqlite::params![skill_id, pattern], |row| {
                                row.get::<_, String>(0)
                            })
                            .map_err(|e| e.to_string())?
                            .filter_map(|r| r.ok())
                            .collect();
                        Ok::<_, String>(keys)
                    })
                    .await
                    {
                        Ok(Ok(k)) => k,
                        Ok(Err(e)) => {
                            caller.data_mut().last_error = Some(e);
                            return 0i64;
                        }
                        Err(e) => {
                            caller.data_mut().last_error = Some(e.to_string());
                            return 0i64;
                        }
                    };

                    let json_bytes = serde_json::to_vec(&keys).unwrap_or_default();

                    let alloc_fn = match caller.get_export("__encmind_alloc") {
                        Some(wasmtime::Extern::Func(f)) => match f.typed::<i32, i32>(&caller) {
                            Ok(tf) => tf,
                            Err(_) => return 0i64,
                        },
                        _ => return 0i64,
                    };

                    match abi::write_to_guest(
                        &alloc_fn,
                        caller.as_context_mut(),
                        &memory,
                        &json_bytes,
                    )
                    .await
                    {
                        Ok(fat) => fat,
                        Err(e) => {
                            caller.data_mut().last_error = Some(e.to_string());
                            0i64
                        }
                    }
                })
            },
        )
        .map_err(|e| WasmHostError::HostFunctionError(format!("kv.list registration: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::runtime::WasmRuntime;

    #[tokio::test]
    async fn kv_host_functions_register() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_kv_get" (func $kv_get (param i32 i32) (result i64)))
            (import "encmind" "__encmind_kv_set" (func $kv_set (param i32 i32 i32 i32) (result i32)))
            (import "encmind" "__encmind_kv_delete" (func $kv_del (param i32 i32) (result i32)))
            (import "encmind" "__encmind_kv_list" (func $kv_list (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (func (export "run") (result i32)
                i32.const 1
            )
        )"#;
        rt.load_module("kv", wat.as_bytes()).unwrap();
        let result = rt.invoke("kv", "run").await.unwrap();
        assert_eq!(result, 1);
    }
}
