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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_connect_roundtrip() {
        let msg = ClientMessage::Connect {
            auth: AuthPayload {
                device_id: "dev-1".into(),
                nonce: "abc123".into(),
                signature: "sig456".into(),
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"connect""#));
        let back: ClientMessage = serde_json::from_str(&json).unwrap();
        match back {
            ClientMessage::Connect { auth } => {
                assert_eq!(auth.device_id, "dev-1");
                assert_eq!(auth.nonce, "abc123");
                assert_eq!(auth.signature, "sig456");
            }
            _ => panic!("Expected Connect"),
        }
    }

    #[test]
    fn client_req_roundtrip() {
        let msg = ClientMessage::Req {
            id: "r1".into(),
            method: "chat.send".into(),
            params: serde_json::json!({"text": "hello"}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"req""#));
        let back: ClientMessage = serde_json::from_str(&json).unwrap();
        match back {
            ClientMessage::Req { id, method, params } => {
                assert_eq!(id, "r1");
                assert_eq!(method, "chat.send");
                assert_eq!(params["text"], "hello");
            }
            _ => panic!("Expected Req"),
        }
    }

    #[test]
    fn client_ping_roundtrip() {
        let msg = ClientMessage::Ping { seq: 42 };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ClientMessage = serde_json::from_str(&json).unwrap();
        match back {
            ClientMessage::Ping { seq } => assert_eq!(seq, 42),
            _ => panic!("Expected Ping"),
        }
    }

    #[test]
    fn server_connected_roundtrip() {
        let json = r#"{"type":"connected","session_id":"ws-dev1"}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::Connected { session_id } => assert_eq!(session_id, "ws-dev1"),
            _ => panic!("Expected Connected"),
        }
    }

    #[test]
    fn server_res_roundtrip() {
        let json = r#"{"type":"res","id":"r1","result":{"ok":true}}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "r1");
                assert_eq!(result["ok"], true);
            }
            _ => panic!("Expected Res"),
        }
    }

    #[test]
    fn server_error_roundtrip() {
        let json = r#"{"type":"error","id":"r1","error":{"code":4001,"message":"auth failed"}}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("r1".into()));
                assert_eq!(error.code, 4001);
                assert_eq!(error.message, "auth failed");
            }
            _ => panic!("Expected Error"),
        }
    }

    #[test]
    fn server_error_null_id() {
        let json = r#"{"type":"error","id":null,"error":{"code":5000,"message":"internal"}}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::Error { id, error } => {
                assert!(id.is_none());
                assert_eq!(error.code, 5000);
            }
            _ => panic!("Expected Error"),
        }
    }

    #[test]
    fn server_event_roundtrip() {
        let json = r#"{"type":"event","event":"chat.token","data":{"delta":"Hi"}}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::Event { event, data } => {
                assert_eq!(event, "chat.token");
                assert_eq!(data["delta"], "Hi");
            }
            _ => panic!("Expected Event"),
        }
    }

    #[test]
    fn server_pong_roundtrip() {
        let json = r#"{"type":"pong","seq":99}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::Pong { seq } => assert_eq!(seq, 99),
            _ => panic!("Expected Pong"),
        }
    }

    #[test]
    fn auth_payload_roundtrip() {
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
    fn client_req_default_params() {
        let json = r#"{"type":"req","id":"r1","method":"sessions.list"}"#;
        let msg: ClientMessage = serde_json::from_str(json).unwrap();
        match msg {
            ClientMessage::Req { params, .. } => {
                assert!(params.is_null());
            }
            _ => panic!("Expected Req"),
        }
    }
}
