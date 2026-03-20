//! `net.*` host functions — outbound HTTP from WASM skills.

use encmind_core::error::WasmHostError;
use wasmtime::{AsContext, AsContextMut, Linker};

use crate::abi;
use crate::host_functions::capability::check_net_outbound;
use crate::runtime::StoreState;
use crate::secret_scanner;

/// Maximum response body size: 4 MiB.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Request timeout: 30 seconds.
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Register net host functions on the linker.
pub fn register(linker: &mut Linker<StoreState>) -> Result<(), WasmHostError> {
    // __encmind_net_fetch(url_ptr, url_len) -> i64 (fat ptr to JSON response)
    linker
        .func_wrap_async(
            "encmind",
            "__encmind_net_fetch",
            |mut caller: wasmtime::Caller<'_, StoreState>, (url_ptr, url_len): (i32, i32)| {
                Box::new(async move {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => {
                            caller.data_mut().last_error = Some("no memory export".into());
                            return 0i64;
                        }
                    };

                    let url_str = match abi::read_guest_string(
                        &memory,
                        caller.as_context(),
                        url_ptr,
                        url_len,
                    ) {
                        Ok(u) => u,
                        Err(e) => {
                            caller.data_mut().last_error = Some(e.to_string());
                            return 0i64;
                        }
                    };

                    // Parse URL and check domain
                    let url = match url::Url::parse(&url_str) {
                        Ok(u) => u,
                        Err(e) => {
                            caller.data_mut().last_error = Some(format!("invalid URL: {e}"));
                            return 0i64;
                        }
                    };

                    let domain = url.host_str().unwrap_or("");
                    if let Err(e) = check_net_outbound(domain, &caller.data().capabilities) {
                        caller.data_mut().last_error = Some(e.to_string());
                        return 0i64;
                    }

                    if let Some(policy) = caller.data().outbound_policy.clone() {
                        if let Err(e) = policy.check_url(&url_str).await {
                            caller.data_mut().last_error = Some(e);
                            return 0i64;
                        }
                    }

                    let client = match caller.data().http_client.as_ref() {
                        Some(c) => c.clone(),
                        None => {
                            caller.data_mut().last_error = Some("no HTTP client available".into());
                            return 0i64;
                        }
                    };

                    let response = match tokio::time::timeout(
                        std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS),
                        client.get(&url_str).send(),
                    )
                    .await
                    {
                        Ok(Ok(resp)) => resp,
                        Ok(Err(e)) => {
                            caller.data_mut().last_error = Some(format!("fetch failed: {e}"));
                            return 0i64;
                        }
                        Err(_) => {
                            caller.data_mut().last_error = Some("fetch timeout".into());
                            return 0i64;
                        }
                    };

                    let status = response.status().as_u16();
                    let headers: serde_json::Map<String, serde_json::Value> = response
                        .headers()
                        .iter()
                        .filter_map(|(k, v)| {
                            v.to_str()
                                .ok()
                                .map(|s| (k.to_string(), serde_json::Value::String(s.into())))
                        })
                        .collect();

                    let body_bytes = match response.bytes().await {
                        Ok(b) => b,
                        Err(e) => {
                            caller.data_mut().last_error = Some(format!("body read failed: {e}"));
                            return 0i64;
                        }
                    };

                    if body_bytes.len() > MAX_RESPONSE_BYTES {
                        caller.data_mut().last_error = Some(format!(
                            "response too large: {} > {MAX_RESPONSE_BYTES}",
                            body_bytes.len()
                        ));
                        return 0i64;
                    }

                    let body_str = String::from_utf8_lossy(&body_bytes);

                    // Secret scan
                    if let Err(e) = secret_scanner::scan(&body_str) {
                        caller.data_mut().last_error = Some(e.to_string());
                        return 0i64;
                    }

                    let result = serde_json::json!({
                        "status": status,
                        "headers": headers,
                        "body": body_str.as_ref(),
                    });

                    let result_bytes = serde_json::to_vec(&result).unwrap_or_default();

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
                        &result_bytes,
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
        .map_err(|e| WasmHostError::HostFunctionError(format!("net.fetch registration: {e}")))?;

    // __encmind_net_http_request(req_ptr, req_len) -> i64
    linker
        .func_wrap_async(
            "encmind",
            "__encmind_net_http_request",
            |mut caller: wasmtime::Caller<'_, StoreState>, (req_ptr, req_len): (i32, i32)| {
                Box::new(async move {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => {
                            caller.data_mut().last_error = Some("no memory export".into());
                            return 0i64;
                        }
                    };

                    let req_json = match abi::read_guest_string(
                        &memory,
                        caller.as_context(),
                        req_ptr,
                        req_len,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            caller.data_mut().last_error = Some(e.to_string());
                            return 0i64;
                        }
                    };

                    let req: serde_json::Value = match serde_json::from_str(&req_json) {
                        Ok(v) => v,
                        Err(e) => {
                            caller.data_mut().last_error =
                                Some(format!("invalid request JSON: {e}"));
                            return 0i64;
                        }
                    };

                    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
                    let url_str = match req.get("url").and_then(|v| v.as_str()) {
                        Some(u) => u.to_string(),
                        None => {
                            caller.data_mut().last_error = Some("missing url field".into());
                            return 0i64;
                        }
                    };

                    let url = match url::Url::parse(&url_str) {
                        Ok(u) => u,
                        Err(e) => {
                            caller.data_mut().last_error = Some(format!("invalid URL: {e}"));
                            return 0i64;
                        }
                    };

                    let domain = url.host_str().unwrap_or("");
                    if let Err(e) = check_net_outbound(domain, &caller.data().capabilities) {
                        caller.data_mut().last_error = Some(e.to_string());
                        return 0i64;
                    }

                    if let Some(policy) = caller.data().outbound_policy.clone() {
                        if let Err(e) = policy.check_url(&url_str).await {
                            caller.data_mut().last_error = Some(e);
                            return 0i64;
                        }
                    }

                    let client = match caller.data().http_client.as_ref() {
                        Some(c) => c.clone(),
                        None => {
                            caller.data_mut().last_error = Some("no HTTP client".into());
                            return 0i64;
                        }
                    };

                    let http_method = match method.to_uppercase().as_str() {
                        "GET" => reqwest::Method::GET,
                        "POST" => reqwest::Method::POST,
                        "PUT" => reqwest::Method::PUT,
                        "DELETE" => reqwest::Method::DELETE,
                        "PATCH" => reqwest::Method::PATCH,
                        "HEAD" => reqwest::Method::HEAD,
                        other => {
                            caller.data_mut().last_error =
                                Some(format!("unsupported method: {other}"));
                            return 0i64;
                        }
                    };

                    let mut builder = client.request(http_method, &url_str);

                    if let Some(headers) = req.get("headers").and_then(|v| v.as_object()) {
                        for (k, v) in headers {
                            if let Some(val) = v.as_str() {
                                builder = builder.header(k.as_str(), val);
                            }
                        }
                    }

                    if let Some(body) = req.get("body").and_then(|v| v.as_str()) {
                        builder = builder.body(body.to_string());
                    }

                    let response = match tokio::time::timeout(
                        std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS),
                        builder.send(),
                    )
                    .await
                    {
                        Ok(Ok(resp)) => resp,
                        Ok(Err(e)) => {
                            caller.data_mut().last_error = Some(format!("request failed: {e}"));
                            return 0i64;
                        }
                        Err(_) => {
                            caller.data_mut().last_error = Some("request timeout".into());
                            return 0i64;
                        }
                    };

                    let status = response.status().as_u16();
                    let resp_headers: serde_json::Map<String, serde_json::Value> = response
                        .headers()
                        .iter()
                        .filter_map(|(k, v)| {
                            v.to_str()
                                .ok()
                                .map(|s| (k.to_string(), serde_json::Value::String(s.into())))
                        })
                        .collect();

                    let body_bytes = match response.bytes().await {
                        Ok(b) => b,
                        Err(e) => {
                            caller.data_mut().last_error = Some(format!("body read: {e}"));
                            return 0i64;
                        }
                    };

                    if body_bytes.len() > MAX_RESPONSE_BYTES {
                        caller.data_mut().last_error =
                            Some(format!("response too large: {}", body_bytes.len()));
                        return 0i64;
                    }

                    let body_str = String::from_utf8_lossy(&body_bytes);
                    if let Err(e) = secret_scanner::scan(&body_str) {
                        caller.data_mut().last_error = Some(e.to_string());
                        return 0i64;
                    }

                    let result = serde_json::json!({
                        "status": status,
                        "headers": resp_headers,
                        "body": body_str.as_ref(),
                    });

                    let result_bytes = serde_json::to_vec(&result).unwrap_or_default();

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
                        &result_bytes,
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
        .map_err(|e| {
            WasmHostError::HostFunctionError(format!("net.http_request registration: {e}"))
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::runtime::WasmRuntime;

    #[tokio::test]
    async fn net_host_functions_register() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_net_fetch" (func $fetch (param i32 i32) (result i64)))
            (import "encmind" "__encmind_net_http_request" (func $http (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (func (export "run") (result i32)
                i32.const 1
            )
        )"#;
        rt.load_module("net", wat.as_bytes()).unwrap();
        let result = rt.invoke("net", "run").await.unwrap();
        assert_eq!(result, 1);
    }

    #[tokio::test]
    async fn net_fetch_denied_without_capability() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_net_fetch" (func $fetch (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (data (i32.const 0) "https://example.com")
            (func (export "run") (result i32)
                (i64.eqz (call $fetch (i32.const 0) (i32.const 19)))
                ;; Should return 0 (null fat ptr) → i64.eqz → 1
            )
        )"#;
        rt.load_module("net_deny", wat.as_bytes()).unwrap();
        let result = rt.invoke("net_deny", "run").await.unwrap();
        assert_eq!(result, 1); // 0 fat ptr (denied) → eqz → 1
    }
}
