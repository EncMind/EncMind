use rusqlite::Connection;

use encmind_core::error::StorageError;

/// Run embedded migrations to bring the database up to the current schema version.
/// Uses `PRAGMA user_version` to track applied migrations.
pub fn run_migrations(conn: &Connection) -> Result<(), StorageError> {
    let version: u32 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| StorageError::MigrationFailed(e.to_string()))?;

    if version < 1 {
        migrate_v1(conn)?;
    }

    if version < 2 {
        migrate_v2(conn)?;
    }

    if version < 3 {
        migrate_v3(conn)?;
    }

    if version < 4 {
        migrate_v4(conn)?;
    }

    if version < 5 {
        migrate_v5(conn)?;
    }

    if version < 6 {
        migrate_v6(conn)?;
    }

    if version < 7 {
        migrate_v7(conn)?;
    }

    if version < 8 {
        migrate_v8(conn)?;
    }

    if version < 9 {
        migrate_v9(conn)?;
    }

    if version < 10 {
        migrate_v10(conn)?;
    }

    Ok(())
}

/// Version 1: Create all 14 tables and indexes.
fn migrate_v1(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(V1_SCHEMA)
        .map_err(|e| StorageError::MigrationFailed(format!("v1 migration failed: {e}")))?;
    conn.pragma_update(None, "user_version", 1u32)
        .map_err(|e| StorageError::MigrationFailed(format!("v1 version update failed: {e}")))
}

const V1_SCHEMA: &str = r#"
-- 3.1 app_config
CREATE TABLE IF NOT EXISTS app_config (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    blob        BLOB    NOT NULL,
    nonce       BLOB    NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1,
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- 3.9 agents (must come before sessions due to FK)
CREATE TABLE IF NOT EXISTS agents (
    id          TEXT    PRIMARY KEY,
    name        TEXT    NOT NULL,
    model       TEXT,
    workspace   TEXT,
    system_prompt TEXT,
    skills      TEXT    NOT NULL DEFAULT '[]',
    config      TEXT    NOT NULL DEFAULT '{}',
    is_default  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Insert default agent if not exists
INSERT OR IGNORE INTO agents (id, name, is_default) VALUES ('main', 'Main Assistant', 1);

-- 3.2 sessions
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT    PRIMARY KEY,
    title       TEXT,
    channel     TEXT    NOT NULL DEFAULT 'web',
    agent_id    TEXT    NOT NULL DEFAULT 'main' REFERENCES agents(id),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    archived    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_channel ON sessions(channel);
CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);

-- 3.3 messages
CREATE TABLE IF NOT EXISTS messages (
    id          TEXT    PRIMARY KEY,
    session_id  TEXT    NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    role        TEXT    NOT NULL,
    content     BLOB    NOT NULL,
    nonce       BLOB    NOT NULL,
    token_count INTEGER,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, created_at);

-- 3.4 tasks
CREATE TABLE IF NOT EXISTS tasks (
    id          TEXT    PRIMARY KEY,
    session_id  TEXT    REFERENCES sessions(id) ON DELETE SET NULL,
    title       TEXT    NOT NULL,
    description TEXT,
    status      TEXT    NOT NULL DEFAULT 'pending',
    due_at      TEXT,
    recurrence  TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, due_at);

-- 3.5 cron_jobs
CREATE TABLE IF NOT EXISTS cron_jobs (
    id          TEXT    PRIMARY KEY,
    name        TEXT    NOT NULL,
    schedule    TEXT    NOT NULL,
    prompt      TEXT    NOT NULL,
    agent_id    TEXT    NOT NULL DEFAULT 'main' REFERENCES agents(id),
    model       TEXT,
    max_concurrent_runs INTEGER NOT NULL DEFAULT 4,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_run_at TEXT,
    next_run_at TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- 3.6 audit_log (hash-chained)
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    category    TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    detail      TEXT,
    source      TEXT,
    prev_hash   BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_category ON audit_log(category, timestamp DESC);

-- 3.7 paired_devices
CREATE TABLE IF NOT EXISTS paired_devices (
    id          TEXT    PRIMARY KEY,
    name        TEXT    NOT NULL,
    public_key  BLOB    NOT NULL,
    permissions TEXT    NOT NULL DEFAULT '{}',
    paired_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen   TEXT
);

-- 3.8 api_keys
CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT    PRIMARY KEY,
    key_blob    BLOB    NOT NULL,
    nonce       BLOB    NOT NULL,
    provider    TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- 3.10 memory_entries
CREATE TABLE IF NOT EXISTS memory_entries (
    id              TEXT    PRIMARY KEY,
    session_id      TEXT    REFERENCES sessions(id) ON DELETE SET NULL,
    qdrant_point_id TEXT    NOT NULL,
    summary         TEXT,
    source_channel  TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_memory_session ON memory_entries(session_id);

-- 3.11 webhook_endpoints
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id              TEXT    PRIMARY KEY,
    name            TEXT    NOT NULL,
    service         TEXT    NOT NULL,
    secret_blob     BLOB,
    secret_nonce    BLOB,
    agent_id        TEXT    NOT NULL DEFAULT 'main' REFERENCES agents(id),
    session_id      TEXT    REFERENCES sessions(id) ON DELETE SET NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_triggered_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_service ON webhook_endpoints(service);

-- 3.12 key_versions
CREATE TABLE IF NOT EXISTS key_versions (
    version     INTEGER PRIMARY KEY,
    key_blob    BLOB    NOT NULL,
    nonce       BLOB    NOT NULL,
    algorithm   TEXT    NOT NULL DEFAULT 'aes-256-gcm',
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    retired_at  TEXT,
    row_count   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_key_versions_active ON key_versions(retired_at) WHERE retired_at IS NULL;

-- 3.13 workflow_runs
CREATE TABLE IF NOT EXISTS workflow_runs (
    id              TEXT    PRIMARY KEY,
    workflow_name   TEXT    NOT NULL,
    agent_id        TEXT    NOT NULL REFERENCES agents(id),
    session_id      TEXT    REFERENCES sessions(id) ON DELETE SET NULL,
    status          TEXT    NOT NULL DEFAULT 'running',
    current_step    INTEGER NOT NULL DEFAULT 0,
    total_steps     INTEGER,
    checkpoint_blob BLOB,
    checkpoint_nonce BLOB,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    max_retries     INTEGER NOT NULL DEFAULT 3,
    error_detail    TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    completed_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_status ON workflow_runs(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_agent ON workflow_runs(agent_id);

-- 3.14 timeline_events
CREATE TABLE IF NOT EXISTS timeline_events (
    id              TEXT    PRIMARY KEY,
    event_type      TEXT    NOT NULL,
    source          TEXT    NOT NULL,
    session_id      TEXT    REFERENCES sessions(id) ON DELETE SET NULL,
    agent_id        TEXT    NOT NULL DEFAULT 'main' REFERENCES agents(id),
    summary         TEXT    NOT NULL,
    detail          TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_timeline_events_ts ON timeline_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_timeline_events_source ON timeline_events(source, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_timeline_events_type ON timeline_events(event_type, created_at DESC);
"#;

/// Version 2: Rename qdrant_point_id → vector_point_id, add source_device,
/// FTS5 table, and vector storage table.
fn migrate_v2(conn: &Connection) -> Result<(), StorageError> {
    // Run v2 as a single transaction so a mid-migration failure does not
    // leave partially applied schema changes with user_version still < 2.
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StorageError::MigrationFailed(format!("v2 transaction start failed: {e}")))?;

    tx.execute_batch(V2_SCHEMA)
        .map_err(|e| StorageError::MigrationFailed(format!("v2 migration failed: {e}")))?;

    tx.pragma_update(None, "user_version", 2u32)
        .map_err(|e| StorageError::MigrationFailed(format!("v2 version update failed: {e}")))?;

    tx.commit()
        .map_err(|e| StorageError::MigrationFailed(format!("v2 transaction commit failed: {e}")))
}

const V2_SCHEMA: &str = r#"
-- Rename qdrant_point_id to vector_point_id
ALTER TABLE memory_entries RENAME COLUMN qdrant_point_id TO vector_point_id;

-- Add source_device column
ALTER TABLE memory_entries ADD COLUMN source_device TEXT;

-- Indexes for source fields
CREATE INDEX IF NOT EXISTS idx_memory_source_device ON memory_entries(source_device);
CREATE INDEX IF NOT EXISTS idx_memory_source_channel ON memory_entries(source_channel);

-- FTS5 virtual table for full-text search on summaries
CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(memory_id, summary);

-- Backfill FTS with any pre-v2 memory entries
INSERT INTO memory_fts(memory_id, summary) SELECT id, summary FROM memory_entries;

-- Vector storage table (f32 BLOB)
CREATE TABLE IF NOT EXISTS memory_vectors (
    point_id    TEXT PRIMARY KEY,
    vector      BLOB NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"#;

/// Version 3: Add per-skill key-value storage table.
fn migrate_v3(conn: &Connection) -> Result<(), StorageError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StorageError::MigrationFailed(format!("v3 transaction start failed: {e}")))?;

    tx.execute_batch(V3_SCHEMA)
        .map_err(|e| StorageError::MigrationFailed(format!("v3 migration failed: {e}")))?;

    tx.pragma_update(None, "user_version", 3u32)
        .map_err(|e| StorageError::MigrationFailed(format!("v3 version update failed: {e}")))?;

    tx.commit()
        .map_err(|e| StorageError::MigrationFailed(format!("v3 transaction commit failed: {e}")))
}

const V3_SCHEMA: &str = r#"
-- Per-skill key-value persistence (Phase 2 WASM host functions)
CREATE TABLE IF NOT EXISTS skill_kv (
    skill_id    TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       BLOB NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (skill_id, key)
);
"#;

/// Version 4: Skill timers table for scheduled skill execution.
fn migrate_v4(conn: &Connection) -> Result<(), StorageError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StorageError::MigrationFailed(format!("v4 transaction start failed: {e}")))?;

    tx.execute_batch(V4_SCHEMA)
        .map_err(|e| StorageError::MigrationFailed(format!("v4 migration failed: {e}")))?;

    tx.pragma_update(None, "user_version", 4u32)
        .map_err(|e| StorageError::MigrationFailed(format!("v4 version update failed: {e}")))?;

    tx.commit()
        .map_err(|e| StorageError::MigrationFailed(format!("v4 transaction commit failed: {e}")))
}

fn migrate_v5(conn: &Connection) -> Result<(), StorageError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StorageError::MigrationFailed(format!("v5 transaction start failed: {e}")))?;

    tx.execute_batch(V5_SCHEMA)
        .map_err(|e| StorageError::MigrationFailed(format!("v5 migration failed: {e}")))?;

    tx.pragma_update(None, "user_version", 5u32)
        .map_err(|e| StorageError::MigrationFailed(format!("v5 version update failed: {e}")))?;

    tx.commit()
        .map_err(|e| StorageError::MigrationFailed(format!("v5 transaction commit failed: {e}")))
}

const V5_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS skill_toggle_state (
    skill_id   TEXT PRIMARY KEY,
    enabled    INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"#;

const V4_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS skill_timers (
    id                   TEXT PRIMARY KEY,
    skill_id             TEXT NOT NULL,
    timer_name           TEXT NOT NULL,
    interval_secs        INTEGER NOT NULL,
    export_fn            TEXT NOT NULL,
    enabled              INTEGER NOT NULL DEFAULT 1,
    last_tick_at         TEXT,
    next_tick_at         TEXT,
    source_manifest_hash TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(skill_id, timer_name)
);
CREATE INDEX IF NOT EXISTS idx_skill_timers_next_tick
    ON skill_timers(enabled, next_tick_at);
"#;

/// Version 6: Channel accounts + encrypted credentials tables.
fn migrate_v6(conn: &Connection) -> Result<(), StorageError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StorageError::MigrationFailed(format!("v6 transaction start failed: {e}")))?;

    tx.execute_batch(V6_SCHEMA)
        .map_err(|e| StorageError::MigrationFailed(format!("v6 migration failed: {e}")))?;

    tx.pragma_update(None, "user_version", 6u32)
        .map_err(|e| StorageError::MigrationFailed(format!("v6 version update failed: {e}")))?;

    tx.commit()
        .map_err(|e| StorageError::MigrationFailed(format!("v6 transaction commit failed: {e}")))
}

/// Version 7: enforce one account per channel_type at the DB layer.
///
/// Historical builds already enforced this in application logic, but races could
/// still insert duplicates. Before creating the unique index, keep the most
/// recently inserted row per channel_type and delete older duplicates.
fn migrate_v7(conn: &Connection) -> Result<(), StorageError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StorageError::MigrationFailed(format!("v7 transaction start failed: {e}")))?;

    tx.execute_batch(V7_SCHEMA)
        .map_err(|e| StorageError::MigrationFailed(format!("v7 migration failed: {e}")))?;

    tx.pragma_update(None, "user_version", 7u32)
        .map_err(|e| StorageError::MigrationFailed(format!("v7 version update failed: {e}")))?;

    tx.commit()
        .map_err(|e| StorageError::MigrationFailed(format!("v7 transaction commit failed: {e}")))
}

fn migrate_v8(conn: &Connection) -> Result<(), StorageError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StorageError::MigrationFailed(format!("v8 transaction start failed: {e}")))?;

    tx.execute_batch(V8_SCHEMA)
        .map_err(|e| StorageError::MigrationFailed(format!("v8 migration failed: {e}")))?;

    tx.pragma_update(None, "user_version", 8u32)
        .map_err(|e| StorageError::MigrationFailed(format!("v8 version update failed: {e}")))?;

    tx.commit()
        .map_err(|e| StorageError::MigrationFailed(format!("v8 transaction commit failed: {e}")))
}

fn migrate_v9(conn: &Connection) -> Result<(), StorageError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StorageError::MigrationFailed(format!("v9 transaction start failed: {e}")))?;

    tx.execute_batch(V9_SCHEMA)
        .map_err(|e| StorageError::MigrationFailed(format!("v9 migration failed: {e}")))?;

    tx.pragma_update(None, "user_version", 9u32)
        .map_err(|e| StorageError::MigrationFailed(format!("v9 version update failed: {e}")))?;

    tx.commit()
        .map_err(|e| StorageError::MigrationFailed(format!("v9 transaction commit failed: {e}")))
}

fn migrate_v10(conn: &Connection) -> Result<(), StorageError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StorageError::MigrationFailed(format!("v10 transaction start failed: {e}")))?;

    tx.execute_batch(V10_SCHEMA)
        .map_err(|e| StorageError::MigrationFailed(format!("v10 migration failed: {e}")))?;

    tx.pragma_update(None, "user_version", 10u32)
        .map_err(|e| StorageError::MigrationFailed(format!("v10 version update failed: {e}")))?;

    tx.commit()
        .map_err(|e| StorageError::MigrationFailed(format!("v10 transaction commit failed: {e}")))
}

const V10_SCHEMA: &str = r#"
-- Computed dollar cost for this turn. NULL when the model isn't in
-- the pricing table. Computed at persist time from a static model
-- pricing lookup in the gateway.
ALTER TABLE api_usage ADD COLUMN cost_usd REAL;
"#;

const V9_SCHEMA: &str = r#"
-- Add a status column to api_usage so cancelled and errored turns
-- can be persisted alongside completed ones. Existing rows default
-- to 'completed' (they were written by v8 which only persisted the
-- success path).
ALTER TABLE api_usage ADD COLUMN status TEXT NOT NULL DEFAULT 'completed';
CREATE INDEX IF NOT EXISTS idx_api_usage_status ON api_usage(status);
"#;

const V8_SCHEMA: &str = r#"
-- Per-turn API usage records for cost attribution. One row per
-- completed chat.send, written at response build time. Lets
-- operators answer "how much did Telegram cost last week" or
-- "which cron job is the expensive one" without summing logs.
CREATE TABLE IF NOT EXISTS api_usage (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT    NOT NULL,
    agent_id        TEXT    NOT NULL,
    channel         TEXT    NOT NULL,
    model           TEXT    NOT NULL,
    provider        TEXT    NOT NULL,
    input_tokens    INTEGER NOT NULL,
    output_tokens   INTEGER NOT NULL,
    total_tokens    INTEGER NOT NULL,
    iterations      INTEGER NOT NULL,
    duration_ms     INTEGER NOT NULL,
    started_at      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_usage_started_at ON api_usage(started_at);
CREATE INDEX IF NOT EXISTS idx_api_usage_session ON api_usage(session_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_channel ON api_usage(channel);
CREATE INDEX IF NOT EXISTS idx_api_usage_agent ON api_usage(agent_id);
"#;

const V6_SCHEMA: &str = r#"
-- Channel accounts managed via API or config
CREATE TABLE IF NOT EXISTS channel_accounts (
    id              TEXT    PRIMARY KEY,
    channel_type    TEXT    NOT NULL,
    label           TEXT    NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    status          TEXT    NOT NULL DEFAULT 'stopped',
    config_source   TEXT    NOT NULL DEFAULT 'api',
    policy_json     TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_channel_accounts_type ON channel_accounts(channel_type);

-- Encrypted credentials for channel accounts
CREATE TABLE IF NOT EXISTS channel_credentials (
    account_id      TEXT    PRIMARY KEY REFERENCES channel_accounts(id) ON DELETE CASCADE,
    cred_blob       BLOB    NOT NULL,
    nonce           BLOB    NOT NULL,
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"#;

const V7_SCHEMA: &str = r#"
-- Keep one row per channel_type, preferring rows with credentials, then newer
-- timestamps, then latest rowid as tie-breaker.
DELETE FROM channel_accounts
WHERE id IN (
    SELECT id
    FROM (
        SELECT
            ca.id,
            ROW_NUMBER() OVER (
                PARTITION BY ca.channel_type
                ORDER BY
                    CASE WHEN cc.account_id IS NOT NULL THEN 1 ELSE 0 END DESC,
                    ca.updated_at DESC,
                    ca.created_at DESC,
                    ca.rowid DESC
            ) AS rn
        FROM channel_accounts ca
        LEFT JOIN channel_credentials cc ON cc.account_id = ca.id
    ) ranked
    WHERE rn > 1
);

-- Enforce uniqueness at the database level to prevent race-condition duplicates.
CREATE UNIQUE INDEX IF NOT EXISTS idx_channel_accounts_type_unique
    ON channel_accounts(channel_type);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    const CURRENT_VERSION: u32 = 10;

    #[test]
    fn migration_creates_all_tables() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        let expected_tables = [
            "app_config",
            "agents",
            "sessions",
            "messages",
            "tasks",
            "cron_jobs",
            "audit_log",
            "paired_devices",
            "api_keys",
            "memory_entries",
            "webhook_endpoints",
            "key_versions",
            "workflow_runs",
            "timeline_events",
            "skill_kv",
            "skill_timers",
            "skill_toggle_state",
        ];

        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .unwrap();
        let tables: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        for table in &expected_tables {
            assert!(
                tables.contains(&table.to_string()),
                "Missing table: {table}. Found: {tables:?}"
            );
        }
    }

    #[test]
    fn migration_sets_user_version() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, CURRENT_VERSION);
    }

    #[test]
    fn migration_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();
        // Running again should not error
        run_migrations(&conn).unwrap();
    }

    #[test]
    fn default_agent_exists() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        let name: String = conn
            .query_row("SELECT name FROM agents WHERE id = 'main'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(name, "Main Assistant");
    }

    #[test]
    fn v2_migration_runs() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        // Run only v1, then verify v2 applies
        migrate_v1(&conn).unwrap();
        conn.pragma_update(None, "user_version", 1u32).unwrap();
        migrate_v2(&conn).unwrap();
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 2);
    }

    #[test]
    fn v2_idempotent_after_v1() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();
        // Running again should not error
        run_migrations(&conn).unwrap();
    }

    #[test]
    fn v2_vector_point_id_column_exists() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        let mut stmt = conn.prepare("PRAGMA table_info(memory_entries)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(
            columns.contains(&"vector_point_id".to_string()),
            "Expected vector_point_id column, found: {columns:?}"
        );
        assert!(
            !columns.contains(&"qdrant_point_id".to_string()),
            "qdrant_point_id should be renamed"
        );
    }

    #[test]
    fn v2_source_device_column_exists() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        let mut stmt = conn.prepare("PRAGMA table_info(memory_entries)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(columns.contains(&"source_device".to_string()));
    }

    #[test]
    fn v2_memory_fts_table_exists() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='memory_fts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "memory_fts table should exist");
    }

    #[test]
    fn v2_memory_vectors_table_exists() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='memory_vectors'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "memory_vectors table should exist");
    }

    #[test]
    fn v2_migration_backfills_existing_entries_into_fts() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

        // Run only v1
        migrate_v1(&conn).unwrap();
        conn.pragma_update(None, "user_version", 1u32).unwrap();

        // Insert a pre-v2 memory entry (uses v1 column name qdrant_point_id)
        conn.execute(
            "INSERT INTO memory_entries (id, qdrant_point_id, summary, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "mem-old",
                "pt-old",
                "user prefers dark mode",
                "2024-01-01T00:00:00Z"
            ],
        )
        .unwrap();

        // Run remaining migrations (v2 should backfill FTS)
        run_migrations(&conn).unwrap();

        // Verify FTS contains the backfilled entry
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memory_fts WHERE memory_fts MATCH '\"dark mode\"'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "pre-v2 entry should appear in FTS after migration"
        );
    }

    #[test]
    fn v2_migration_rolls_back_on_mid_batch_failure() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

        // Start at v1 schema.
        migrate_v1(&conn).unwrap();
        conn.pragma_update(None, "user_version", 1u32).unwrap();

        // Pre-create a column that v2 also tries to add. This forces v2 to fail
        // after the rename step has executed, which catches partial-apply bugs.
        conn.execute_batch("ALTER TABLE memory_entries ADD COLUMN source_device TEXT;")
            .unwrap();

        let err = run_migrations(&conn).unwrap_err();
        assert!(
            err.to_string().contains("v2 migration failed"),
            "unexpected error: {err}"
        );

        // user_version should remain unchanged on failure.
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);

        // Rename should have been rolled back as part of the failed transaction.
        let mut stmt = conn.prepare("PRAGMA table_info(memory_entries)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(columns.contains(&"qdrant_point_id".to_string()));
        assert!(!columns.contains(&"vector_point_id".to_string()));
    }

    #[test]
    fn v3_migration_runs() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        // Run only up to v3
        migrate_v1(&conn).unwrap();
        conn.pragma_update(None, "user_version", 1u32).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
    }

    #[test]
    fn v3_skill_kv_table_exists() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='skill_kv'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "skill_kv table should exist");
    }

    #[test]
    fn v3_skill_kv_crud() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        // Insert
        conn.execute(
            "INSERT INTO skill_kv (skill_id, key, value) VALUES (?1, ?2, ?3)",
            rusqlite::params!["skill-a", "config", b"hello"],
        )
        .unwrap();

        // Read
        let val: Vec<u8> = conn
            .query_row(
                "SELECT value FROM skill_kv WHERE skill_id = ?1 AND key = ?2",
                rusqlite::params!["skill-a", "config"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(val, b"hello");

        // Upsert (INSERT OR REPLACE)
        conn.execute(
            "INSERT OR REPLACE INTO skill_kv (skill_id, key, value, updated_at) \
             VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
            rusqlite::params!["skill-a", "config", b"world"],
        )
        .unwrap();

        let val2: Vec<u8> = conn
            .query_row(
                "SELECT value FROM skill_kv WHERE skill_id = ?1 AND key = ?2",
                rusqlite::params!["skill-a", "config"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(val2, b"world");

        // Delete
        conn.execute(
            "DELETE FROM skill_kv WHERE skill_id = ?1 AND key = ?2",
            rusqlite::params!["skill-a", "config"],
        )
        .unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM skill_kv WHERE skill_id = 'skill-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn v3_skill_kv_cross_skill_isolation() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        conn.execute(
            "INSERT INTO skill_kv (skill_id, key, value) VALUES (?1, ?2, ?3)",
            rusqlite::params!["skill-a", "key1", b"val-a"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO skill_kv (skill_id, key, value) VALUES (?1, ?2, ?3)",
            rusqlite::params!["skill-b", "key1", b"val-b"],
        )
        .unwrap();

        // Same key name but different values per skill
        let val_a: Vec<u8> = conn
            .query_row(
                "SELECT value FROM skill_kv WHERE skill_id = ?1 AND key = ?2",
                rusqlite::params!["skill-a", "key1"],
                |row| row.get(0),
            )
            .unwrap();
        let val_b: Vec<u8> = conn
            .query_row(
                "SELECT value FROM skill_kv WHERE skill_id = ?1 AND key = ?2",
                rusqlite::params!["skill-b", "key1"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(val_a, b"val-a");
        assert_eq!(val_b, b"val-b");
    }

    #[test]
    fn v3_skill_kv_list_with_prefix() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        conn.execute(
            "INSERT INTO skill_kv (skill_id, key, value) VALUES (?1, ?2, ?3)",
            rusqlite::params!["skill-a", "config.theme", b"dark"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO skill_kv (skill_id, key, value) VALUES (?1, ?2, ?3)",
            rusqlite::params!["skill-a", "config.lang", b"en"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO skill_kv (skill_id, key, value) VALUES (?1, ?2, ?3)",
            rusqlite::params!["skill-a", "data.cache", b"x"],
        )
        .unwrap();

        let mut stmt = conn
            .prepare("SELECT key FROM skill_kv WHERE skill_id = ?1 AND key LIKE ?2 ORDER BY key")
            .unwrap();
        let keys: Vec<String> = stmt
            .query_map(rusqlite::params!["skill-a", "config.%"], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert_eq!(keys, vec!["config.lang", "config.theme"]);
    }

    #[test]
    fn v3_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();
        run_migrations(&conn).unwrap();
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, CURRENT_VERSION);
    }

    #[test]
    fn v4_migration_runs() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, CURRENT_VERSION);
    }

    #[test]
    fn v4_skill_timers_table_exists() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='skill_timers'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "skill_timers table should exist");
    }

    #[test]
    fn v4_skill_timers_unique_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        conn.execute(
            "INSERT INTO skill_timers (id, skill_id, timer_name, interval_secs, export_fn) \
             VALUES ('t1', 'skill-a', 'daily', 3600, '__tick')",
            [],
        )
        .unwrap();

        // Same skill_id + timer_name should fail
        let err = conn.execute(
            "INSERT INTO skill_timers (id, skill_id, timer_name, interval_secs, export_fn) \
             VALUES ('t2', 'skill-a', 'daily', 7200, '__tick2')",
            [],
        );
        assert!(err.is_err(), "duplicate skill_id+timer_name should fail");
    }

    #[test]
    fn v4_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();
        run_migrations(&conn).unwrap();
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, CURRENT_VERSION);
    }

    #[test]
    fn v4_preserves_v3_data() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

        // Run up to v3
        migrate_v1(&conn).unwrap();
        conn.pragma_update(None, "user_version", 1u32).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();

        // Insert v3 data
        conn.execute(
            "INSERT INTO skill_kv (skill_id, key, value) VALUES ('skill-a', 'key1', X'DEADBEEF')",
            [],
        )
        .unwrap();

        // Run v4
        migrate_v4(&conn).unwrap();

        // Verify v3 data still exists
        let val: Vec<u8> = conn
            .query_row(
                "SELECT value FROM skill_kv WHERE skill_id = 'skill-a' AND key = 'key1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(val, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn audit_log_has_prev_hash_column() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        // Verify prev_hash column exists by querying table info
        let mut stmt = conn.prepare("PRAGMA table_info(audit_log)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert!(columns.contains(&"prev_hash".to_string()));
    }

    #[test]
    fn v5_migration_creates_skill_toggle_table() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='skill_toggle_state'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "skill_toggle_state table should exist");
    }

    #[test]
    fn v5_skill_toggle_crud() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        // Insert
        conn.execute(
            "INSERT INTO skill_toggle_state (skill_id, enabled) VALUES ('skill-a', 0)",
            [],
        )
        .unwrap();

        let enabled: i64 = conn
            .query_row(
                "SELECT enabled FROM skill_toggle_state WHERE skill_id = 'skill-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(enabled, 0);

        // Update
        conn.execute(
            "UPDATE skill_toggle_state SET enabled = 1 WHERE skill_id = 'skill-a'",
            [],
        )
        .unwrap();

        let enabled2: i64 = conn
            .query_row(
                "SELECT enabled FROM skill_toggle_state WHERE skill_id = 'skill-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(enabled2, 1);
    }

    #[test]
    fn v6_migration_creates_channel_tables() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='channel_accounts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "channel_accounts table should exist");

        let count2: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='channel_credentials'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count2, 1, "channel_credentials table should exist");
    }

    #[test]
    fn v6_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();
        run_migrations(&conn).unwrap();
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, CURRENT_VERSION);
    }

    #[test]
    fn v6_channel_credentials_fk_cascade() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        conn.execute(
            "INSERT INTO channel_accounts (id, channel_type, label) VALUES ('acct-1', 'telegram', 'Bot')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO channel_credentials (account_id, cred_blob, nonce) VALUES ('acct-1', X'AABB', X'CCDD')",
            [],
        )
        .unwrap();

        // Delete the account; FK cascade should remove the credential
        conn.execute("DELETE FROM channel_accounts WHERE id = 'acct-1'", [])
            .unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM channel_credentials WHERE account_id = 'acct-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "credentials should be cascaded on account delete");
    }

    #[test]
    fn v6_preserves_v5_data() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

        // Run up to v5
        migrate_v1(&conn).unwrap();
        conn.pragma_update(None, "user_version", 1u32).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();
        migrate_v4(&conn).unwrap();
        migrate_v5(&conn).unwrap();

        conn.execute(
            "INSERT INTO skill_toggle_state (skill_id, enabled) VALUES ('skill-a', 0)",
            [],
        )
        .unwrap();

        // Run v6
        migrate_v6(&conn).unwrap();

        let enabled: i64 = conn
            .query_row(
                "SELECT enabled FROM skill_toggle_state WHERE skill_id = 'skill-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(enabled, 0, "v5 data should be preserved after v6 migration");
    }

    #[test]
    fn v7_enforces_unique_channel_type() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&conn).unwrap();

        conn.execute(
            "INSERT INTO channel_accounts (id, channel_type, label) VALUES ('acct-1', 'telegram', 'Bot 1')",
            [],
        )
        .unwrap();

        let err = conn
            .execute(
                "INSERT INTO channel_accounts (id, channel_type, label) VALUES ('acct-2', 'telegram', 'Bot 2')",
                [],
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("UNIQUE constraint failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn v7_deduplicates_existing_channel_type_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

        // Build schema up to v6 (no unique channel_type index yet).
        migrate_v1(&conn).unwrap();
        conn.pragma_update(None, "user_version", 1u32).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();
        migrate_v4(&conn).unwrap();
        migrate_v5(&conn).unwrap();
        migrate_v6(&conn).unwrap();

        conn.execute(
            "INSERT INTO channel_accounts (id, channel_type, label) VALUES ('acct-1', 'telegram', 'Old')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO channel_accounts (id, channel_type, label) VALUES ('acct-2', 'telegram', 'New')",
            [],
        )
        .unwrap();
        // The older row has a credential; dedupe should preserve it.
        conn.execute(
            "INSERT INTO channel_credentials (account_id, cred_blob, nonce) VALUES ('acct-1', X'AABB', X'CCDD')",
            [],
        )
        .unwrap();

        migrate_v7(&conn).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM channel_accounts WHERE channel_type = 'telegram'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "v7 should deduplicate duplicate channel_type rows"
        );

        let survivor_id: String = conn
            .query_row(
                "SELECT id FROM channel_accounts WHERE channel_type = 'telegram'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        // v7 prefers rows with credentials over rows without.
        assert_eq!(survivor_id, "acct-1");
    }
}
