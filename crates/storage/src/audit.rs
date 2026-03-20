use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use sha2::{Digest, Sha256};

use encmind_core::error::StorageError;

/// Hash-chained audit logger.
///
/// Each entry includes a `prev_hash` that chains to the previous entry,
/// making tampering immediately detectable.
pub struct AuditLogger {
    pool: Pool<SqliteConnectionManager>,
}

/// A single audit log entry.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: String,
    pub category: String,
    pub action: String,
    pub detail: Option<String>,
    pub source: Option<String>,
    pub prev_hash: Vec<u8>,
}

/// An error found during chain verification.
#[derive(Debug, Clone)]
pub struct ChainError {
    pub entry_id: i64,
    pub expected_hash: Vec<u8>,
    pub actual_hash: Vec<u8>,
}

/// Audit log query filter.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub category: Option<String>,
    pub action: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    /// Filter by skill ID — matches actions starting with `skill.{skill_id}.`.
    pub skill_id: Option<String>,
}

impl AuditLogger {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }

    /// Append a new entry to the audit log with hash chaining.
    pub fn append(
        &self,
        category: &str,
        action: &str,
        detail: Option<&str>,
        source: Option<&str>,
    ) -> Result<(), StorageError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        // Read previous hash and append in one write transaction.
        let prev_hash = self.get_last_hash(&tx)?;

        tx.execute(
            "INSERT INTO audit_log (category, action, detail, source, prev_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![category, action, detail, source, prev_hash],
        )
        .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        tx.commit()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        Ok(())
    }

    /// Verify the integrity of the entire audit chain.
    /// Returns a list of errors (empty = chain is valid).
    pub fn verify_chain(&self) -> Result<Vec<ChainError>, StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let mut stmt = conn
            .prepare("SELECT id, timestamp, category, action, detail, source, prev_hash FROM audit_log ORDER BY id ASC")
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let entries: Vec<AuditEntry> = stmt
            .query_map([], |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    category: row.get(2)?,
                    action: row.get(3)?,
                    detail: row.get(4)?,
                    source: row.get(5)?,
                    prev_hash: row.get(6)?,
                })
            })
            .map_err(|e| StorageError::Sqlite(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let mut errors = Vec::new();
        let mut expected_hash = genesis_hash();

        for entry in &entries {
            if entry.prev_hash != expected_hash {
                errors.push(ChainError {
                    entry_id: entry.id,
                    expected_hash: expected_hash.clone(),
                    actual_hash: entry.prev_hash.clone(),
                });
            }

            // Compute the hash that the NEXT entry should reference
            expected_hash = compute_entry_hash(entry);
        }

        Ok(errors)
    }

    /// Query the audit log with optional filters.
    pub fn query(
        &self,
        filter: AuditFilter,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditEntry>, StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let mut sql = String::from(
            "SELECT id, timestamp, category, action, detail, source, prev_hash FROM audit_log WHERE 1=1",
        );
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref cat) = filter.category {
            sql.push_str(&format!(" AND category = ?{}", params.len() + 1));
            params.push(Box::new(cat.clone()));
        }
        if let Some(ref act) = filter.action {
            sql.push_str(&format!(" AND action = ?{}", params.len() + 1));
            params.push(Box::new(act.clone()));
        }
        if let Some(ref since) = filter.since {
            sql.push_str(&format!(" AND timestamp >= ?{}", params.len() + 1));
            params.push(Box::new(since.clone()));
        }
        if let Some(ref until) = filter.until {
            sql.push_str(&format!(" AND timestamp <= ?{}", params.len() + 1));
            params.push(Box::new(until.clone()));
        }
        if let Some(ref skill_id) = filter.skill_id {
            let escaped = escape_like_pattern(skill_id);
            let action_pattern = format!("skill.{escaped}.%");
            let legacy_detail_pattern = format!("%\\\"skill_id\\\":\\\"{escaped}\\\"%");
            // Legacy fallback for historical rows that recorded timer_auto_disabled
            // without source. New rows are matched by source equality.
            //
            // Prefer JSON-path matching for legacy rows. For malformed historical
            // detail payloads, keep a conservative string fallback so skill-scoped
            // audit queries remain operational.
            sql.push_str(&format!(
                " AND (action LIKE ?{} ESCAPE '\\' OR \
                 (action = 'timer_auto_disabled' AND \
                  (source = ?{} OR (source IS NULL AND detail IS NOT NULL \
                   AND ((json_valid(detail) = 1 AND json_extract(detail, '$.skill_id') = ?{}) \
                    OR (json_valid(detail) = 0 AND detail LIKE ?{} ESCAPE '\\'))))))",
                params.len() + 1,
                params.len() + 2,
                params.len() + 3,
                params.len() + 4
            ));
            params.push(Box::new(action_pattern));
            params.push(Box::new(skill_id.clone()));
            params.push(Box::new(skill_id.clone()));
            params.push(Box::new(legacy_detail_pattern));
        }

        sql.push_str(" ORDER BY timestamp DESC");
        sql.push_str(&format!(
            " LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2
        ));
        params.push(Box::new(limit));
        params.push(Box::new(offset));

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let entries = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    category: row.get(2)?,
                    action: row.get(3)?,
                    detail: row.get(4)?,
                    source: row.get(5)?,
                    prev_hash: row.get(6)?,
                })
            })
            .map_err(|e| StorageError::Sqlite(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        Ok(entries)
    }

    /// Get the hash that the next entry should reference.
    fn get_last_hash(&self, conn: &rusqlite::Connection) -> Result<Vec<u8>, StorageError> {
        let result = conn.query_row(
            "SELECT id, timestamp, category, action, detail, source, prev_hash FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    category: row.get(2)?,
                    action: row.get(3)?,
                    detail: row.get(4)?,
                    source: row.get(5)?,
                    prev_hash: row.get(6)?,
                })
            },
        );

        match result {
            Ok(entry) => Ok(compute_entry_hash(&entry)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(genesis_hash()),
            Err(e) => Err(StorageError::Sqlite(e.to_string())),
        }
    }
}

fn escape_like_pattern(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '%' | '_' | '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Genesis hash: SHA-256(b"genesis").
fn genesis_hash() -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"genesis");
    hasher.finalize().to_vec()
}

/// Compute the hash of an audit entry.
/// SHA-256(id || timestamp || category || action || detail || prev_hash)
fn compute_entry_hash(entry: &AuditEntry) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(entry.id.to_string().as_bytes());
    hasher.update(b"||");
    hasher.update(entry.timestamp.as_bytes());
    hasher.update(b"||");
    hasher.update(entry.category.as_bytes());
    hasher.update(b"||");
    hasher.update(entry.action.as_bytes());
    hasher.update(b"||");
    hasher.update(entry.detail.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"||");
    hasher.update(&entry.prev_hash);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::run_migrations;
    use crate::pool::create_test_pool;
    use std::sync::Arc;

    fn setup() -> AuditLogger {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        AuditLogger::new(pool)
    }

    #[test]
    fn append_single_entry() {
        let logger = setup();
        logger
            .append(
                "auth",
                "login.success",
                Some("user authenticated"),
                Some("web"),
            )
            .unwrap();

        let entries = logger.query(AuditFilter::default(), 10, 0).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].category, "auth");
        assert_eq!(entries[0].action, "login.success");
    }

    #[test]
    fn genesis_entry_has_genesis_hash() {
        let logger = setup();
        logger.append("system", "startup", None, None).unwrap();

        let entries = logger.query(AuditFilter::default(), 10, 0).unwrap();
        assert_eq!(entries[0].prev_hash, genesis_hash());
    }

    #[test]
    fn chain_is_valid_after_multiple_entries() {
        let logger = setup();
        logger.append("auth", "login", None, Some("web")).unwrap();
        logger
            .append(
                "skill",
                "web_search.invoke",
                Some("{\"query\":\"test\"}"),
                Some("agent"),
            )
            .unwrap();
        logger
            .append("tool", "bash.exec", Some("{\"cmd\":\"ls\"}"), Some("agent"))
            .unwrap();

        let errors = logger.verify_chain().unwrap();
        assert!(errors.is_empty(), "Chain should be valid: {errors:?}");
    }

    #[test]
    fn tampered_entry_detected() {
        let logger = setup();
        logger.append("auth", "login", None, None).unwrap();
        logger.append("skill", "invoke", None, None).unwrap();
        logger.append("tool", "bash.exec", None, None).unwrap();

        // Tamper with the second entry (scope connection so it's released)
        {
            let conn = logger.pool.get().unwrap();
            conn.execute("UPDATE audit_log SET action = 'TAMPERED' WHERE id = 2", [])
                .unwrap();
        }

        let errors = logger.verify_chain().unwrap();
        // The third entry should detect the tamper because entry 2's hash changed
        assert!(!errors.is_empty(), "Tampering should be detected");
    }

    #[test]
    fn verify_empty_chain() {
        let logger = setup();
        let errors = logger.verify_chain().unwrap();
        assert!(errors.is_empty());
    }

    #[test]
    fn query_with_category_filter() {
        let logger = setup();
        logger.append("auth", "login", None, None).unwrap();
        logger.append("skill", "invoke", None, None).unwrap();
        logger.append("auth", "logout", None, None).unwrap();

        let auth_entries = logger
            .query(
                AuditFilter {
                    category: Some("auth".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(auth_entries.len(), 2);
    }

    #[test]
    fn query_with_pagination() {
        let logger = setup();
        for i in 0..10 {
            logger
                .append("test", &format!("action-{i}"), None, None)
                .unwrap();
        }

        let page1 = logger.query(AuditFilter::default(), 3, 0).unwrap();
        assert_eq!(page1.len(), 3);

        let page2 = logger.query(AuditFilter::default(), 3, 3).unwrap();
        assert_eq!(page2.len(), 3);

        // Pages should not overlap
        assert_ne!(page1[0].id, page2[0].id);
    }

    #[test]
    fn query_filters_by_skill_id() {
        let logger = setup();
        logger
            .append("skill", "skill.my-skill.invoke", Some("{}"), Some("agent"))
            .unwrap();
        logger
            .append("skill", "skill.my-skill.timer_tick", None, None)
            .unwrap();
        logger
            .append("skill", "skill.other-skill.invoke", Some("{}"), None)
            .unwrap();
        logger.append("keys", "set", Some("openai"), None).unwrap();

        let entries = logger
            .query(
                AuditFilter {
                    skill_id: Some("my-skill".into()),
                    ..Default::default()
                },
                100,
                0,
            )
            .unwrap();
        assert_eq!(entries.len(), 2);
        for e in &entries {
            assert!(e.action.starts_with("skill.my-skill."));
        }
    }

    #[test]
    fn query_filters_by_skill_id_treats_underscore_as_literal() {
        let logger = setup();
        logger
            .append("skill", "skill.foo_bar.invoke", Some("{}"), Some("agent"))
            .unwrap();
        logger
            .append("skill", "skill.fooxbar.invoke", Some("{}"), Some("agent"))
            .unwrap();

        let entries = logger
            .query(
                AuditFilter {
                    skill_id: Some("foo_bar".into()),
                    ..Default::default()
                },
                100,
                0,
            )
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "skill.foo_bar.invoke");
    }

    #[test]
    fn query_filters_by_skill_id_includes_timer_auto_disabled_events() {
        let logger = setup();
        logger
            .append(
                "skill",
                "timer_auto_disabled",
                Some(r#"{"skill_id":"my-skill","reason":"too many failures"}"#),
                Some("my-skill"),
            )
            .unwrap();
        logger
            .append(
                "skill",
                "timer_auto_disabled",
                Some(r#"{"skill_id":"other-skill","reason":"too many failures"}"#),
                Some("other-skill"),
            )
            .unwrap();
        logger
            .append(
                "skill",
                "timer_auto_disabled",
                Some(r#"{"skill_id":"my-skill","reason":"legacy row"}"#),
                None,
            )
            .unwrap();

        let entries = logger
            .query(
                AuditFilter {
                    skill_id: Some("my-skill".into()),
                    ..Default::default()
                },
                100,
                0,
            )
            .unwrap();

        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.action == "timer_auto_disabled"));
        assert!(entries.iter().all(|e| e
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("\"skill_id\":\"my-skill\"")));
    }

    #[test]
    fn query_filters_by_skill_id_legacy_fallback_uses_root_skill_id_field() {
        let logger = setup();
        logger
            .append(
                "skill",
                "timer_auto_disabled",
                Some(r#"{"skill_id":"my-skill","reason":"legacy row"}"#),
                None,
            )
            .unwrap();
        logger
            .append(
                "skill",
                "timer_auto_disabled",
                Some(r#"{"skill_id":"other-skill","nested":{"skill_id":"my-skill"}}"#),
                None,
            )
            .unwrap();

        let entries = logger
            .query(
                AuditFilter {
                    skill_id: Some("my-skill".into()),
                    ..Default::default()
                },
                100,
                0,
            )
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].detail.as_deref(),
            Some(r#"{"skill_id":"my-skill","reason":"legacy row"}"#)
        );
    }

    #[test]
    fn query_filters_by_skill_id_legacy_fallback_includes_malformed_json_detail() {
        let logger = setup();
        logger
            .append(
                "skill",
                "timer_auto_disabled",
                Some(r#"{"skill_id":"my-skill","reason":"broken""#),
                None,
            )
            .unwrap();
        logger
            .append(
                "skill",
                "timer_auto_disabled",
                Some(r#"{"skill_id":"other-skill","reason":"broken""#),
                None,
            )
            .unwrap();

        let entries = logger
            .query(
                AuditFilter {
                    skill_id: Some("my-skill".into()),
                    ..Default::default()
                },
                100,
                0,
            )
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].detail.as_deref(),
            Some(r#"{"skill_id":"my-skill","reason":"broken""#)
        );
    }

    #[test]
    fn query_without_skill_id_returns_all() {
        let logger = setup();
        logger
            .append("skill", "skill.a.invoke", None, None)
            .unwrap();
        logger
            .append("skill", "skill.b.invoke", None, None)
            .unwrap();
        logger.append("keys", "set", None, None).unwrap();

        let entries = logger.query(AuditFilter::default(), 100, 0).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn concurrent_appends_keep_chain_valid() {
        let logger = Arc::new(setup());
        let mut handles = Vec::new();

        for i in 0..20 {
            let logger = Arc::clone(&logger);
            handles.push(std::thread::spawn(move || {
                let detail = format!("entry-{i}");
                logger
                    .append("concurrency", "append", Some(&detail), Some("test"))
                    .unwrap();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let errors = logger.verify_chain().unwrap();
        assert!(
            errors.is_empty(),
            "expected valid chain after concurrent appends, got: {errors:?}"
        );
    }
}
