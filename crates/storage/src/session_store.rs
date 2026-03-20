use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::StorageError;
use encmind_core::traits::{EncryptionAdapter, SessionStore};
use encmind_core::types::*;

/// SQLite-backed session store with per-row encryption for message content.
pub struct SqliteSessionStore {
    pool: Pool<SqliteConnectionManager>,
    encryption: Arc<dyn EncryptionAdapter>,
}

impl SqliteSessionStore {
    pub fn new(
        pool: Pool<SqliteConnectionManager>,
        encryption: Arc<dyn EncryptionAdapter>,
    ) -> Self {
        Self { pool, encryption }
    }
}

#[async_trait]
impl SessionStore for SqliteSessionStore {
    async fn create_session(&self, channel: &str) -> Result<Session, StorageError> {
        self.create_session_for_agent(channel, &AgentId::default())
            .await
    }

    async fn create_session_for_agent(
        &self,
        channel: &str,
        agent_id: &AgentId,
    ) -> Result<Session, StorageError> {
        let id = SessionId::new();
        let now = Utc::now();
        let channel = channel.to_owned();

        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let id_str = id.as_str().to_owned();
        let agent_str = agent_id.as_str().to_owned();
        let now_str = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        conn.execute(
            "INSERT INTO sessions (id, channel, agent_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![id_str, channel, agent_str, now_str, now_str],
        )
        .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        Ok(Session {
            id,
            title: None,
            channel,
            agent_id: agent_id.clone(),
            created_at: now,
            updated_at: now,
            archived: false,
        })
    }

    async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let id_str = id.as_str().to_owned();
        let result = conn.query_row(
            "SELECT id, title, channel, agent_id, created_at, updated_at, archived FROM sessions WHERE id = ?1",
            rusqlite::params![id_str],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        );

        match result {
            Ok((session_id, title, channel, agent_id, created_at, updated_at, archived)) => {
                Ok(Some(Session {
                    id: SessionId::from_string(session_id),
                    title,
                    channel,
                    agent_id: AgentId::new(agent_id),
                    created_at: parse_datetime(&created_at)?,
                    updated_at: parse_datetime(&updated_at)?,
                    archived: archived != 0,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StorageError::Sqlite(e.to_string())),
        }
    }

    async fn list_sessions(&self, filter: SessionFilter) -> Result<Vec<Session>, StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let mut sql = String::from(
            "SELECT id, title, channel, agent_id, created_at, updated_at, archived FROM sessions WHERE 1=1",
        );
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref channel) = filter.channel {
            sql.push_str(&format!(" AND channel = ?{}", params.len() + 1));
            params.push(Box::new(channel.clone()));
        }
        if let Some(ref agent_id) = filter.agent_id {
            sql.push_str(&format!(" AND agent_id = ?{}", params.len() + 1));
            params.push(Box::new(agent_id.as_str().to_owned()));
        }
        if let Some(archived) = filter.archived {
            sql.push_str(&format!(" AND archived = ?{}", params.len() + 1));
            params.push(Box::new(archived as i64));
        }

        sql.push_str(" ORDER BY updated_at DESC");

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let session_rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .map_err(|e| StorageError::Sqlite(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let mut sessions = Vec::with_capacity(session_rows.len());
        for (session_id, title, channel, agent_id, created_at, updated_at, archived) in session_rows
        {
            sessions.push(Session {
                id: SessionId::from_string(session_id),
                title,
                channel,
                agent_id: AgentId::new(agent_id),
                created_at: parse_datetime(&created_at)?,
                updated_at: parse_datetime(&updated_at)?,
                archived: archived != 0,
            });
        }

        Ok(sessions)
    }

    async fn rename_session(&self, id: &SessionId, title: &str) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let rows = conn
            .execute(
                "UPDATE sessions SET title = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![title, now, id.as_str()],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        if rows == 0 {
            return Err(StorageError::NotFound(format!("session {id}")));
        }
        Ok(())
    }

    async fn delete_session(&self, id: &SessionId) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let rows = conn
            .execute(
                "DELETE FROM sessions WHERE id = ?1",
                rusqlite::params![id.as_str()],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        if rows == 0 {
            return Err(StorageError::NotFound(format!("session {id}")));
        }
        Ok(())
    }

    async fn append_message(
        &self,
        session_id: &SessionId,
        msg: &Message,
    ) -> Result<(), StorageError> {
        // Serialize content to JSON, then encrypt
        let content_json = serde_json::to_vec(&msg.content)
            .map_err(|e| StorageError::InvalidData(e.to_string()))?;
        let (ciphertext, nonce) = self.encryption.encrypt(&content_json)?;

        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let role_str = serde_json::to_string(&msg.role)
            .map_err(|e| StorageError::InvalidData(e.to_string()))?;
        // Remove quotes from serialized role
        let role_str = role_str.trim_matches('"');
        let created_str = msg.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        conn.execute(
            "INSERT INTO messages (id, session_id, role, content, nonce, token_count, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                msg.id.as_str(),
                session_id.as_str(),
                role_str,
                ciphertext,
                nonce,
                msg.token_count,
                created_str,
            ],
        )
        .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        // Update session's updated_at
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        conn.execute(
            "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
            rusqlite::params![now, session_id.as_str()],
        )
        .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        Ok(())
    }

    async fn get_messages(
        &self,
        session_id: &SessionId,
        pagination: Pagination,
    ) -> Result<Vec<Message>, StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, role, content, nonce, token_count, created_at FROM messages WHERE session_id = ?1 ORDER BY created_at ASC LIMIT ?2 OFFSET ?3",
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let encryption = &self.encryption;

        let messages = stmt
            .query_map(
                rusqlite::params![session_id.as_str(), pagination.limit, pagination.offset],
                |row| {
                    let id = MessageId::from_string(row.get::<_, String>(0)?);
                    let role_str: String = row.get(1)?;
                    let ciphertext: Vec<u8> = row.get(2)?;
                    let nonce: Vec<u8> = row.get(3)?;
                    let token_count: Option<u32> = row.get(4)?;
                    let created_at_str: String = row.get(5)?;

                    Ok((id, role_str, ciphertext, nonce, token_count, created_at_str))
                },
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let mut result = Vec::new();
        for row in messages {
            let (id, role_str, ciphertext, nonce, token_count, created_at_str) =
                row.map_err(|e| StorageError::Sqlite(e.to_string()))?;

            let plaintext = encryption.decrypt(&ciphertext, &nonce)?;
            let content: Vec<ContentBlock> = serde_json::from_slice(&plaintext)
                .map_err(|e| StorageError::InvalidData(e.to_string()))?;
            let role: Role = serde_json::from_str(&format!("\"{role_str}\""))
                .map_err(|e| StorageError::InvalidData(e.to_string()))?;

            result.push(Message {
                id,
                role,
                content,
                created_at: parse_datetime(&created_at_str)?,
                token_count,
            });
        }

        Ok(result)
    }

    async fn compact_session(
        &self,
        session_id: &SessionId,
        keep_last: usize,
    ) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        conn.execute(
            "DELETE FROM messages WHERE session_id = ?1 AND id NOT IN (SELECT id FROM messages WHERE session_id = ?1 ORDER BY created_at DESC LIMIT ?2)",
            rusqlite::params![session_id.as_str(), keep_last as i64],
        )
        .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        Ok(())
    }
}

/// Parse an ISO-8601 datetime string to chrono::DateTime<Utc>.
fn parse_datetime(s: &str) -> Result<chrono::DateTime<Utc>, StorageError> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ")
        .map(|naive| naive.and_utc())
        .map_err(|e| StorageError::InvalidData(format!("invalid timestamp '{s}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::Aes256GcmAdapter;
    use crate::migrations::run_migrations;
    use crate::pool::create_test_pool;

    fn setup() -> SqliteSessionStore {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        let encryption = Arc::new(Aes256GcmAdapter::new(&[0x42u8; 32]));
        SqliteSessionStore::new(pool, encryption)
    }

    #[tokio::test]
    async fn create_and_get_session() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        assert_eq!(session.channel, "web");
        assert!(session.title.is_none());

        let fetched = store.get_session(&session.id).await.unwrap().unwrap();
        assert_eq!(fetched.id, session.id);
        assert_eq!(fetched.channel, "web");
    }

    #[tokio::test]
    async fn get_nonexistent_session() {
        let store = setup();
        let result = store
            .get_session(&SessionId::from_string("nonexistent"))
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn rename_session() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        store.rename_session(&session.id, "My Chat").await.unwrap();

        let fetched = store.get_session(&session.id).await.unwrap().unwrap();
        assert_eq!(fetched.title.as_deref(), Some("My Chat"));
    }

    #[tokio::test]
    async fn delete_session() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        store.delete_session(&session.id).await.unwrap();

        let fetched = store.get_session(&session.id).await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn append_and_get_messages() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();

        let msg = Message {
            id: MessageId::new(),
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "Hello, world!".into(),
            }],
            created_at: Utc::now(),
            token_count: Some(5),
        };

        store.append_message(&session.id, &msg).await.unwrap();

        let messages = store
            .get_messages(&session.id, Pagination::default())
            .await
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, msg.id);
        assert_eq!(messages[0].role, Role::User);
        assert_eq!(messages[0].content.len(), 1);
        match &messages[0].content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Hello, world!"),
            _ => panic!("Expected Text content block"),
        }
    }

    #[tokio::test]
    async fn messages_are_encrypted_in_db() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();

        let msg = Message {
            id: MessageId::new(),
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "This is a secret message".into(),
            }],
            created_at: Utc::now(),
            token_count: None,
        };
        store.append_message(&session.id, &msg).await.unwrap();

        // Read raw blob from DB
        let conn = store.pool.get().unwrap();
        let raw_content: Vec<u8> = conn
            .query_row(
                "SELECT content FROM messages WHERE id = ?1",
                rusqlite::params![msg.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();

        // The raw content should NOT contain the plaintext string
        let plaintext = b"This is a secret message";
        let raw_str = String::from_utf8_lossy(&raw_content);
        assert!(
            !raw_str.contains("This is a secret message"),
            "Raw DB content should be encrypted, but found plaintext: {raw_str}"
        );
        assert_ne!(raw_content, plaintext.to_vec());
    }

    #[tokio::test]
    async fn list_sessions_with_filter() {
        let store = setup();
        store.create_session("web").await.unwrap();
        store.create_session("telegram").await.unwrap();
        store.create_session("web").await.unwrap();

        let web_sessions = store
            .list_sessions(SessionFilter {
                channel: Some("web".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(web_sessions.len(), 2);

        let all_sessions = store.list_sessions(SessionFilter::default()).await.unwrap();
        assert_eq!(all_sessions.len(), 3);
    }

    #[tokio::test]
    async fn compact_session_keeps_last_n() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();

        for i in 0..5 {
            let msg = Message {
                id: MessageId::new(),
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: format!("Message {i}"),
                }],
                created_at: Utc::now(),
                token_count: None,
            };
            store.append_message(&session.id, &msg).await.unwrap();
            // Small delay to ensure ordered timestamps
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        store.compact_session(&session.id, 2).await.unwrap();

        let messages = store
            .get_messages(&session.id, Pagination::default())
            .await
            .unwrap();
        assert_eq!(messages.len(), 2);
    }

    #[tokio::test]
    async fn delete_session_cascades_messages() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();

        let msg = Message {
            id: MessageId::new(),
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "test".into(),
            }],
            created_at: Utc::now(),
            token_count: None,
        };
        store.append_message(&session.id, &msg).await.unwrap();

        store.delete_session(&session.id).await.unwrap();

        // Messages should be gone via cascade
        let conn = store.pool.get().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE session_id = ?1",
                rusqlite::params![session.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn invalid_timestamp_returns_error() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();

        {
            let conn = store.pool.get().unwrap();
            conn.execute(
                "UPDATE sessions SET created_at = 'not-a-timestamp' WHERE id = ?1",
                rusqlite::params![session.id.as_str()],
            )
            .unwrap();
        }

        let err = store.get_session(&session.id).await.unwrap_err();
        assert!(matches!(err, StorageError::InvalidData(_)));
    }
}
