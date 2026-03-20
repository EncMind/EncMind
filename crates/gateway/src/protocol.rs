use serde::{Deserialize, Serialize};

/// Messages sent from client → server over WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Initial connection with auth payload.
    Connect { auth: AuthPayload },
    /// JSON-RPC-style request.
    Req {
        id: String,
        method: String,
        #[serde(default)]
        params: serde_json::Value,
    },
    /// Keepalive ping.
    Ping { seq: u64 },
}

/// Messages sent from server → client over WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Successful connection acknowledgement.
    Connected { session_id: String },
    /// Response to a Req.
    Res {
        id: String,
        result: serde_json::Value,
    },
    /// Server-initiated event (streaming tokens, status changes, etc.).
    Event {
        event: String,
        data: serde_json::Value,
    },
    /// Keepalive pong.
    Pong { seq: u64 },
    /// Error response.
    Error {
        id: Option<String>,
        error: ErrorPayload,
    },
}

/// Authentication payload sent during Connect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPayload {
    pub device_id: String,
    pub nonce: String,
    pub signature: String,
}

/// Error details in an Error message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: i32,
    pub message: String,
}

impl ErrorPayload {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

// Standard error codes
pub const ERR_AUTH_FAILED: i32 = 4001;
pub const ERR_UNKNOWN_METHOD: i32 = 4002;
pub const ERR_LOCKDOWN: i32 = 4003;
pub const ERR_RATE_LIMITED: i32 = 4004;
pub const ERR_INVALID_PARAMS: i32 = 4005;
pub const ERR_INTERNAL: i32 = 5000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_connect_serde() {
        let msg = ClientMessage::Connect {
            auth: AuthPayload {
                device_id: "dev-1".into(),
                nonce: "abc".into(),
                signature: "sig".into(),
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ClientMessage = serde_json::from_str(&json).unwrap();
        match back {
            ClientMessage::Connect { auth } => {
                assert_eq!(auth.device_id, "dev-1");
            }
            _ => panic!("Expected Connect"),
        }
    }

    #[test]
    fn client_req_serde() {
        let msg = ClientMessage::Req {
            id: "req-1".into(),
            method: "chat.send".into(),
            params: serde_json::json!({"text": "hello"}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ClientMessage = serde_json::from_str(&json).unwrap();
        match back {
            ClientMessage::Req { id, method, .. } => {
                assert_eq!(id, "req-1");
                assert_eq!(method, "chat.send");
            }
            _ => panic!("Expected Req"),
        }
    }

    #[test]
    fn client_ping_serde() {
        let msg = ClientMessage::Ping { seq: 42 };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ClientMessage = serde_json::from_str(&json).unwrap();
        match back {
            ClientMessage::Ping { seq } => assert_eq!(seq, 42),
            _ => panic!("Expected Ping"),
        }
    }

    #[test]
    fn server_connected_serde() {
        let msg = ServerMessage::Connected {
            session_id: "ses-1".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ServerMessage = serde_json::from_str(&json).unwrap();
        match back {
            ServerMessage::Connected { session_id } => {
                assert_eq!(session_id, "ses-1");
            }
            _ => panic!("Expected Connected"),
        }
    }

    #[test]
    fn server_res_serde() {
        let msg = ServerMessage::Res {
            id: "req-1".into(),
            result: serde_json::json!({"ok": true}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ServerMessage = serde_json::from_str(&json).unwrap();
        match back {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-1");
                assert_eq!(result["ok"], true);
            }
            _ => panic!("Expected Res"),
        }
    }

    #[test]
    fn server_error_serde() {
        let msg = ServerMessage::Error {
            id: Some("req-1".into()),
            error: ErrorPayload::new(ERR_AUTH_FAILED, "bad token"),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ServerMessage = serde_json::from_str(&json).unwrap();
        match back {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-1".into()));
                assert_eq!(error.code, ERR_AUTH_FAILED);
                assert_eq!(error.message, "bad token");
            }
            _ => panic!("Expected Error"),
        }
    }

    #[test]
    fn auth_payload_serde() {
        let auth = AuthPayload {
            device_id: "d1".into(),
            nonce: "n1".into(),
            signature: "s1".into(),
        };
        let json = serde_json::to_string(&auth).unwrap();
        let back: AuthPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.device_id, "d1");
        assert_eq!(back.nonce, "n1");
        assert_eq!(back.signature, "s1");
    }

    #[test]
    fn auth_payload_deserialized_from_json() {
        let json = r#"{"device_id":"d2","nonce":"n2","signature":"s2"}"#;
        let auth: AuthPayload = serde_json::from_str(json).unwrap();
        assert_eq!(auth.device_id, "d2");
    }

    #[test]
    fn error_payload_new() {
        let ep = ErrorPayload::new(5000, "internal error");
        assert_eq!(ep.code, 5000);
        assert_eq!(ep.message, "internal error");
    }
}
