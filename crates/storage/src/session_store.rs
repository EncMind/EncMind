use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::StorageError;
use encmind_core::traits::{EncryptionAdapter, SessionStore};
use encmind_core::types::*;

/// Maximum messages returned in a single session export to prevent unbounded
/// memory usage. Clients needing more can use paginated `chat.history`.
const MAX_EXPORT_MESSAGES: usize = 1000;

/// Maximum total decrypted bytes across all exported messages (~10 MiB).
const MAX_EXPORT_BYTES: usize = 10 * 1024 * 1024;

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
            tags: vec![],
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
                let tags = load_tags(&conn, &session_id)?;
                Ok(Some(Session {
                    id: SessionId::from_string(session_id),
                    title,
                    channel,
                    agent_id: AgentId::new(agent_id),
                    created_at: parse_datetime(&created_at)?,
                    updated_at: parse_datetime(&updated_at)?,
                    archived: archived != 0,
                    tags,
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

        // Batch-load tags for all listed sessions in one query.
        let session_ids: Vec<&str> = session_rows.iter().map(|(id, ..)| id.as_str()).collect();
        let tags_map = load_tags_batch(&conn, &session_ids)?;

        let mut sessions = Vec::with_capacity(session_rows.len());
        for (session_id, title, channel, agent_id, created_at, updated_at, archived) in session_rows
        {
            let tags = tags_map
                .get(session_id.as_str())
                .cloned()
                .unwrap_or_default();
            sessions.push(Session {
                id: SessionId::from_string(session_id),
                title,
                channel,
                agent_id: AgentId::new(agent_id),
                created_at: parse_datetime(&created_at)?,
                updated_at: parse_datetime(&updated_at)?,
                archived: archived != 0,
                tags,
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

    async fn archive_session(&self, id: &SessionId) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let rows = conn
            .execute(
                "UPDATE sessions SET archived = 1, updated_at = ?1 WHERE id = ?2",
                rusqlite::params![now, id.as_str()],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        if rows == 0 {
            return Err(StorageError::NotFound(format!("session {id}")));
        }
        Ok(())
    }

    async fn unarchive_session(&self, id: &SessionId) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let rows = conn
            .execute(
                "UPDATE sessions SET archived = 0, updated_at = ?1 WHERE id = ?2",
                rusqlite::params![now, id.as_str()],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        if rows == 0 {
            return Err(StorageError::NotFound(format!("session {id}")));
        }
        Ok(())
    }

    async fn add_session_tag(&self, id: &SessionId, tag: &str) -> Result<(), StorageError> {
        validate_tag(tag)?;
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        require_session_exists(&tx, id)?;
        let rows = tx
            .execute(
                "INSERT OR IGNORE INTO session_tags (session_id, tag) VALUES (?1, ?2)",
                rusqlite::params![id.as_str(), tag],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        if rows > 0 {
            touch_session_updated_at(&tx, id)?;
        }
        tx.commit()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        Ok(())
    }

    async fn remove_session_tag(&self, id: &SessionId, tag: &str) -> Result<(), StorageError> {
        validate_tag(tag)?;
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        require_session_exists(&tx, id)?;
        let rows = tx
            .execute(
                "DELETE FROM session_tags WHERE session_id = ?1 AND tag = ?2",
                rusqlite::params![id.as_str(), tag],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        if rows > 0 {
            touch_session_updated_at(&tx, id)?;
        }
        tx.commit()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        Ok(())
    }

    async fn get_session_tags(&self, id: &SessionId) -> Result<Vec<String>, StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        require_session_exists(&conn, id)?;
        Ok(load_tags(&conn, id.as_str())?)
    }

    async fn export_session(&self, id: &SessionId) -> Result<SessionExport, StorageError> {
        let session = self
            .get_session(id)
            .await?
            .ok_or_else(|| StorageError::NotFound(format!("session {id}")))?;

        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        // Count total messages for truncation metadata.
        let total_messages: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE session_id = ?1",
                rusqlite::params![id.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        let total_messages = total_messages as u64;

        // Cap export at MAX_EXPORT_MESSAGES to prevent unbounded memory usage.
        let mut stmt = conn
            .prepare(
                "SELECT id, role, content, nonce, token_count, created_at \
                 FROM messages WHERE session_id = ?1 \
                 ORDER BY created_at ASC, rowid ASC \
                 LIMIT ?2",
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let encryption = &self.encryption;
        let rows = stmt
            .query_map(
                rusqlite::params![id.as_str(), MAX_EXPORT_MESSAGES as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Option<u32>>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let mut messages = Vec::new();
        let mut total_bytes: usize = 0;
        let mut byte_cap_hit = false;
        for row in rows {
            let (msg_id, role_str, ciphertext, nonce, token_count, created_at_str) =
                row.map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let plaintext = encryption.decrypt(&ciphertext, &nonce)?;
            total_bytes += plaintext.len();
            if total_bytes > MAX_EXPORT_BYTES {
                byte_cap_hit = true;
                break;
            }
            let content: Vec<ContentBlock> = serde_json::from_slice(&plaintext)
                .map_err(|e| StorageError::InvalidData(e.to_string()))?;
            let role: Role = serde_json::from_str(&format!("\"{role_str}\""))
                .map_err(|e| StorageError::InvalidData(e.to_string()))?;
            messages.push(ExportedMessage {
                id: msg_id,
                role,
                content,
                created_at: parse_datetime(&created_at_str)?,
                token_count,
            });
        }

        let truncated = byte_cap_hit || total_messages > MAX_EXPORT_MESSAGES as u64;
        Ok(SessionExport {
            session,
            messages,
            truncated,
            total_messages,
        })
    }
}

/// Check that a session exists, returning NotFound if not.
fn require_session_exists(conn: &rusqlite::Connection, id: &SessionId) -> Result<(), StorageError> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE id = ?1)",
            rusqlite::params![id.as_str()],
            |row| row.get(0),
        )
        .map_err(|e| StorageError::Sqlite(e.to_string()))?;
    if !exists {
        return Err(StorageError::NotFound(format!("session {id}")));
    }
    Ok(())
}

/// Bump sessions.updated_at to now.
fn touch_session_updated_at(
    conn: &rusqlite::Connection,
    id: &SessionId,
) -> Result<(), StorageError> {
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    conn.execute(
        "UPDATE sessions SET updated_at = ?1 WHERE id = ?2",
        rusqlite::params![now, id.as_str()],
    )
    .map_err(|e| StorageError::Sqlite(e.to_string()))?;
    Ok(())
}

/// Validate a session tag: 1-64 chars, alphanumeric + hyphens + underscores.
fn validate_tag(tag: &str) -> Result<(), StorageError> {
    if tag.is_empty() || tag.len() > 64 {
        return Err(StorageError::ValidationFailed(
            "tag must be 1-64 characters".into(),
        ));
    }
    if !tag
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(StorageError::ValidationFailed(
            "tag must contain only alphanumeric characters, hyphens, and underscores".into(),
        ));
    }
    Ok(())
}

/// Load tags for multiple sessions in one query, returning a map of session_id → tags.
/// SQLite default SQLITE_MAX_VARIABLE_NUMBER is 999.
const BATCH_CHUNK_SIZE: usize = 900;

fn load_tags_batch(
    conn: &rusqlite::Connection,
    session_ids: &[&str],
) -> Result<std::collections::HashMap<String, Vec<String>>, StorageError> {
    use std::collections::HashMap;
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    if session_ids.is_empty() {
        return Ok(map);
    }
    for chunk in session_ids.chunks(BATCH_CHUNK_SIZE) {
        let placeholders: Vec<String> = (1..=chunk.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "SELECT session_id, tag FROM session_tags WHERE session_id IN ({}) ORDER BY session_id, tag",
            placeholders.join(", ")
        );
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        let params: Vec<&dyn rusqlite::types::ToSql> = chunk
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let rows = stmt
            .query_map(params.as_slice(), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        for row in rows {
            let (sid, tag) = row.map_err(|e| StorageError::Sqlite(e.to_string()))?;
            map.entry(sid).or_default().push(tag);
        }
    }
    Ok(map)
}

/// Load tags for a session from the session_tags table.
fn load_tags(conn: &rusqlite::Connection, session_id: &str) -> Result<Vec<String>, StorageError> {
    let mut stmt = conn
        .prepare("SELECT tag FROM session_tags WHERE session_id = ?1 ORDER BY tag")
        .map_err(|e| StorageError::Sqlite(e.to_string()))?;
    let tags = stmt
        .query_map(rusqlite::params![session_id], |row| row.get(0))
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
        .collect::<Result<Vec<String>, _>>()
        .map_err(|e| StorageError::Sqlite(e.to_string()))?;
    Ok(tags)
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

    // ── Archive / Unarchive ───────────────────────────────────

    #[tokio::test]
    async fn archive_and_unarchive_session() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        assert!(!session.archived);

        store.archive_session(&session.id).await.unwrap();
        let archived = store.get_session(&session.id).await.unwrap().unwrap();
        assert!(archived.archived);

        store.unarchive_session(&session.id).await.unwrap();
        let restored = store.get_session(&session.id).await.unwrap().unwrap();
        assert!(!restored.archived);
    }

    #[tokio::test]
    async fn archive_nonexistent_session_returns_not_found() {
        let store = setup();
        let fake = SessionId::from_string("nonexistent");
        let err = store.archive_session(&fake).await.unwrap_err();
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    // ── Tags ──────────────────────────────────────────────────

    #[tokio::test]
    async fn add_and_get_tags() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();

        store
            .add_session_tag(&session.id, "important")
            .await
            .unwrap();
        store
            .add_session_tag(&session.id, "follow-up")
            .await
            .unwrap();

        let tags = store.get_session_tags(&session.id).await.unwrap();
        assert_eq!(tags, vec!["follow-up", "important"]); // sorted
    }

    #[tokio::test]
    async fn duplicate_tag_is_idempotent() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();

        store.add_session_tag(&session.id, "dup").await.unwrap();
        store.add_session_tag(&session.id, "dup").await.unwrap();

        let tags = store.get_session_tags(&session.id).await.unwrap();
        assert_eq!(tags, vec!["dup"]);
    }

    #[tokio::test]
    async fn remove_tag() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();

        store.add_session_tag(&session.id, "a").await.unwrap();
        store.add_session_tag(&session.id, "b").await.unwrap();
        store.remove_session_tag(&session.id, "a").await.unwrap();

        let tags = store.get_session_tags(&session.id).await.unwrap();
        assert_eq!(tags, vec!["b"]);
    }

    #[tokio::test]
    async fn tag_validation_rejects_empty() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        let err = store.add_session_tag(&session.id, "").await.unwrap_err();
        assert!(matches!(err, StorageError::ValidationFailed(_)));
    }

    #[tokio::test]
    async fn tag_validation_rejects_invalid_chars() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        let err = store
            .add_session_tag(&session.id, "has spaces")
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::ValidationFailed(_)));
    }

    #[tokio::test]
    async fn tag_validation_rejects_overlength() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        let long_tag = "a".repeat(65);
        let err = store
            .add_session_tag(&session.id, &long_tag)
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::ValidationFailed(_)));
    }

    #[tokio::test]
    async fn delete_session_cascades_to_tags() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        store.add_session_tag(&session.id, "tagged").await.unwrap();
        store.delete_session(&session.id).await.unwrap();

        // Session is gone — get_session_tags returns NotFound (FK cascaded the rows).
        let err = store.get_session_tags(&session.id).await.unwrap_err();
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[tokio::test]
    async fn get_session_populates_tags() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        store.add_session_tag(&session.id, "t1").await.unwrap();
        store.add_session_tag(&session.id, "t2").await.unwrap();

        let fetched = store.get_session(&session.id).await.unwrap().unwrap();
        assert_eq!(fetched.tags, vec!["t1", "t2"]);
    }

    #[tokio::test]
    async fn list_sessions_populates_tags() {
        let store = setup();
        let s1 = store.create_session("web").await.unwrap();
        let s2 = store.create_session("web").await.unwrap();
        store.add_session_tag(&s1.id, "alpha").await.unwrap();
        store.add_session_tag(&s2.id, "beta").await.unwrap();

        let sessions = store.list_sessions(SessionFilter::default()).await.unwrap();
        assert_eq!(sessions.len(), 2);
        // Each session should have exactly one tag.
        for s in &sessions {
            assert_eq!(s.tags.len(), 1);
        }
    }

    // ── Export ─────────────────────────────────────────────────

    #[tokio::test]
    async fn export_session_includes_messages() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();

        let msg = Message {
            id: MessageId::new(),
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "Hello export".into(),
            }],
            created_at: Utc::now(),
            token_count: Some(3),
        };
        store.append_message(&session.id, &msg).await.unwrap();

        let export = store.export_session(&session.id).await.unwrap();
        assert_eq!(export.session.id, session.id);
        assert_eq!(export.messages.len(), 1);
        assert_eq!(export.messages[0].id, msg.id.as_str());
        assert_eq!(export.messages[0].role, Role::User);
    }

    #[tokio::test]
    async fn export_reports_truncated_false_when_under_limit() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        let msg = Message {
            id: MessageId::new(),
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "small".into(),
            }],
            created_at: Utc::now(),
            token_count: None,
        };
        store.append_message(&session.id, &msg).await.unwrap();

        let export = store.export_session(&session.id).await.unwrap();
        assert!(!export.truncated);
        assert_eq!(export.total_messages, 1);
        assert_eq!(export.messages.len(), 1);
    }

    #[tokio::test]
    async fn export_nonexistent_session_returns_not_found() {
        let store = setup();
        let fake = SessionId::from_string("nonexistent");
        let err = store.export_session(&fake).await.unwrap_err();
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[tokio::test]
    async fn duplicate_tag_add_does_not_bump_updated_at() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        store.add_session_tag(&session.id, "dup").await.unwrap();

        let after_first = store.get_session(&session.id).await.unwrap().unwrap();
        // Sleep >1s so second-precision timestamps would differ if bumped.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        store.add_session_tag(&session.id, "dup").await.unwrap();
        let after_second = store.get_session(&session.id).await.unwrap().unwrap();

        assert_eq!(
            after_first.updated_at, after_second.updated_at,
            "duplicate tag add should not bump updated_at"
        );
    }

    #[tokio::test]
    async fn remove_absent_tag_does_not_bump_updated_at() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        let before = store.get_session(&session.id).await.unwrap().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        store
            .remove_session_tag(&session.id, "nonexistent")
            .await
            .unwrap();
        let after = store.get_session(&session.id).await.unwrap().unwrap();

        assert_eq!(
            before.updated_at, after.updated_at,
            "removing absent tag should not bump updated_at"
        );
    }

    #[tokio::test]
    async fn remove_tag_validates_format() {
        let store = setup();
        let session = store.create_session("web").await.unwrap();
        let err = store
            .remove_session_tag(&session.id, "has spaces")
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::ValidationFailed(_)));
    }
}
