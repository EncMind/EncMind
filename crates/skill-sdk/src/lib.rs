use std::alloc::{alloc, Layout};

pub type SkillInput = serde_json::Value;
pub type SkillOutput = serde_json::Value;

pub trait IntoSkillResult {
    fn into_skill_result(self) -> Result<SkillOutput, String>;
}

impl IntoSkillResult for SkillOutput {
    fn into_skill_result(self) -> Result<SkillOutput, String> {
        Ok(self)
    }
}

impl<E> IntoSkillResult for Result<SkillOutput, E>
where
    E: std::fmt::Display,
{
    fn into_skill_result(self) -> Result<SkillOutput, String> {
        self.map_err(|e| e.to_string())
    }
}

/// Allocate guest memory for host ABI writes.
pub fn alloc_guest(size: i32) -> i32 {
    let layout = Layout::from_size_align(size.max(0) as usize, 1).expect("valid layout");
    // SAFETY: the returned pointer is managed by the guest module linear memory allocator.
    unsafe { alloc(layout) as i32 }
}

/// Decode incoming JSON payload from guest memory.
pub fn decode_input(ptr: i32, len: i32) -> Result<SkillInput, String> {
    if ptr < 0 || len < 0 {
        return Err("invalid negative pointer/length".to_string());
    }
    let len = len as usize;
    // SAFETY: host provides (ptr,len) to module memory. We only read len bytes.
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
    serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON input: {e}"))
}

/// Encode output JSON into guest memory and return fat pointer `(ptr << 32) | len`.
pub fn encode_output(value: &SkillOutput) -> i64 {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|e| {
        let fallback = serde_json::json!({
            "error": format!("failed to serialize output: {e}")
        });
        serde_json::to_vec(&fallback)
            .unwrap_or_else(|_| b"{\"error\":\"serialization failure\"}".to_vec())
    });
    let out_ptr = alloc_guest(bytes.len() as i32);
    // SAFETY: out_ptr points to writable guest memory allocated above.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr as *mut u8, bytes.len());
    }
    ((out_ptr as i64) << 32) | (bytes.len() as i64)
}

/// Execute a skill handler against ABI `(ptr,len)` input and return encoded output.
pub fn invoke_with<F, R>(ptr: i32, len: i32, handler: F) -> i64
where
    F: FnOnce(SkillInput) -> R,
    R: IntoSkillResult,
{
    let output = match decode_input(ptr, len) {
        Ok(input) => match handler(input).into_skill_result() {
            Ok(value) => value,
            Err(err) => serde_json::json!({ "error": err }),
        },
        Err(err) => serde_json::json!({ "error": err }),
    };
    encode_output(&output)
}

/// Export Native ABI entrypoints for a handler function.
///
/// Handler signature can be either:
/// - `fn(serde_json::Value) -> serde_json::Value`
/// - `fn(serde_json::Value) -> Result<serde_json::Value, E>`
#[macro_export]
macro_rules! export_tool {
    ($handler:path) => {
        #[no_mangle]
        pub extern "C" fn __encmind_alloc(size: i32) -> i32 {
            $crate::alloc_guest(size)
        }

        #[no_mangle]
        pub extern "C" fn __encmind_invoke(ptr: i32, len: i32) -> i64 {
            $crate::invoke_with(ptr, len, $handler)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn into_skill_result_accepts_value() {
        let out = serde_json::json!({"ok": true})
            .into_skill_result()
            .expect("value should convert");
        assert_eq!(out["ok"], true);
    }

    #[test]
    fn into_skill_result_accepts_result() {
        let ok: Result<serde_json::Value, String> = Ok(serde_json::json!({"ok": true}));
        let out = ok.into_skill_result().expect("ok should convert");
        assert_eq!(out["ok"], true);

        let err: Result<serde_json::Value, String> = Err("boom".into());
        assert_eq!(err.into_skill_result().unwrap_err(), "boom");
    }
}
