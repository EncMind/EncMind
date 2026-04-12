//! Per-turn API usage persistence for cost attribution.
//!
//! Writes one row per `chat.send` turn — whether it completed,
//! was cancelled, or errored — at response build time. The `status`
//! column distinguishes the three terminal states so operators can
//! filter cost queries by outcome.
//! Supports filter queries over session / agent / channel / status /
//! time range for admin RPCs and operator dashboards.

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::StorageError;

/// A single per-turn API usage record.
#[derive(Debug, Clone)]
pub struct ApiUsageRecord {
    pub id: i64,
    pub session_id: String,
    pub agent_id: String,
    pub channel: String,
    pub model: String,
    pub provider: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub iterations: i64,
    pub duration_ms: i64,
    pub started_at: String,
    /// Terminal status of the turn: `"completed"`, `"cancelled"`, or
    /// `"error"`. Cancelled and errored turns are persisted so cost
    /// attribution reflects tokens that were actually consumed even
    /// if the run didn't complete.
    pub status: String,
    /// Computed USD cost based on the model's pricing table at persist
    /// time. `None` when the model isn't in the pricing table.
    pub cost_usd: Option<f64>,
}

/// Insert parameters (id + started_at are assigned by SQLite).
#[derive(Debug, Clone)]
pub struct ApiUsageInsert<'a> {
    pub session_id: &'a str,
    pub agent_id: &'a str,
    pub channel: &'a str,
    pub model: &'a str,
    pub provider: &'a str,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
    pub iterations: u32,
    pub duration_ms: u64,
    pub started_at: &'a str,
    /// Terminal status: `"completed"`, `"cancelled"`, or `"error"`.
    pub status: &'a str,
    /// Computed USD cost. `None` when model isn't in pricing table.
    pub cost_usd: Option<f64>,
}

/// Query filter for api_usage reads.
#[derive(Debug, Clone, Default)]
pub struct ApiUsageFilter {
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
    pub channel: Option<String>,
    /// Filter by terminal status (e.g. `"cancelled"` to see only
    /// cancelled turns, useful for cost auditing).
    pub status: Option<String>,
    /// ISO-8601 timestamp lower bound (inclusive).
    pub since: Option<String>,
    /// ISO-8601 timestamp upper bound (exclusive).
    pub until: Option<String>,
}

/// Aggregate roll-up returned alongside row results.
#[derive(Debug, Clone, Default)]
pub struct ApiUsageAggregate {
    pub row_count: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub total_duration_ms: i64,
    /// Sum of `cost_usd` across all matching rows. `None` values
    /// (unknown pricing) are excluded from the sum; if every row is
    /// `None`, total_cost_usd is 0.0 (not null).
    pub total_cost_usd: f64,
}

/// Thin wrapper over the `api_usage` table.
pub struct ApiUsageStore {
    pool: Pool<SqliteConnectionManager>,
}

impl ApiUsageStore {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }

    /// Insert a usage row. Best-effort — returns the error so callers
    /// can decide whether to log and continue. The chat.send handler
    /// should NOT fail the response if this insert fails.
    pub fn append(&self, row: &ApiUsageInsert<'_>) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        conn.execute(
            "INSERT INTO api_usage (\
                session_id, agent_id, channel, model, provider, \
                input_tokens, output_tokens, total_tokens, iterations, \
                duration_ms, started_at, status, cost_usd\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                row.session_id,
                row.agent_id,
                row.channel,
                row.model,
                row.provider,
                row.input_tokens as i64,
                row.output_tokens as i64,
                row.total_tokens as i64,
                row.iterations as i64,
                row.duration_ms as i64,
                row.started_at,
                row.status,
                row.cost_usd,
            ],
        )
        .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        Ok(())
    }

    /// Query usage rows with a filter. Caps at `limit` rows (DESC by
    /// started_at). Returns rows plus a rolled-up aggregate across
    /// every row matching the filter (not just the returned page).
    pub fn query(
        &self,
        filter: &ApiUsageFilter,
        limit: u32,
    ) -> Result<(Vec<ApiUsageRecord>, ApiUsageAggregate), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        // Build WHERE clause dynamically.
        let mut where_clauses: Vec<&str> = Vec::new();
        let mut binds: Vec<&dyn rusqlite::ToSql> = Vec::new();

        if let Some(session_id) = &filter.session_id {
            where_clauses.push("session_id = ?");
            binds.push(session_id);
        }
        if let Some(agent_id) = &filter.agent_id {
            where_clauses.push("agent_id = ?");
            binds.push(agent_id);
        }
        if let Some(channel) = &filter.channel {
            where_clauses.push("channel = ?");
            binds.push(channel);
        }
        if let Some(status) = &filter.status {
            where_clauses.push("status = ?");
            binds.push(status);
        }
        if let Some(since) = &filter.since {
            where_clauses.push("julianday(started_at) >= julianday(?)");
            binds.push(since);
        }
        if let Some(until) = &filter.until {
            where_clauses.push("julianday(started_at) < julianday(?)");
            binds.push(until);
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", where_clauses.join(" AND "))
        };

        // Clamp limit to a sensible max so an operator mistake can't
        // load millions of rows into memory.
        let capped_limit = limit.clamp(1, 1000);

        let row_sql = format!(
            "SELECT id, session_id, agent_id, channel, model, provider, \
                    input_tokens, output_tokens, total_tokens, iterations, \
                    duration_ms, started_at, status, cost_usd \
             FROM api_usage{where_sql} \
             ORDER BY julianday(started_at) DESC, id DESC \
             LIMIT {capped_limit}"
        );

        let mut stmt = conn
            .prepare(&row_sql)
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        let rows: Vec<ApiUsageRecord> = stmt
            .query_map(binds.as_slice(), |row| {
                Ok(ApiUsageRecord {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    agent_id: row.get(2)?,
                    channel: row.get(3)?,
                    model: row.get(4)?,
                    provider: row.get(5)?,
                    input_tokens: row.get(6)?,
                    output_tokens: row.get(7)?,
                    total_tokens: row.get(8)?,
                    iterations: row.get(9)?,
                    duration_ms: row.get(10)?,
                    started_at: row.get(11)?,
                    status: row.get(12)?,
                    cost_usd: row.get(13)?,
                })
            })
            .map_err(|e| StorageError::Sqlite(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        // Aggregate across every row matching the filter (ignores limit).
        let agg_sql = format!(
            "SELECT COUNT(*) AS row_count, \
                    COALESCE(SUM(input_tokens), 0), \
                    COALESCE(SUM(output_tokens), 0), \
                    COALESCE(SUM(total_tokens), 0), \
                    COALESCE(SUM(duration_ms), 0), \
                    COALESCE(SUM(cost_usd), 0.0) \
             FROM api_usage{where_sql}"
        );
        let aggregate = conn
            .query_row(&agg_sql, binds.as_slice(), |row| {
                Ok(ApiUsageAggregate {
                    row_count: row.get(0)?,
                    input_tokens: row.get(1)?,
                    output_tokens: row.get(2)?,
                    total_tokens: row.get(3)?,
                    total_duration_ms: row.get(4)?,
                    total_cost_usd: row.get(5)?,
                })
            })
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        Ok((rows, aggregate))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::create_test_pool;
    use chrono::Utc;

    fn store() -> ApiUsageStore {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            crate::migrations::run_migrations(&conn).unwrap();
        }
        ApiUsageStore::new(pool)
    }

    #[test]
    fn append_and_query_round_trip() {
        let store = store();
        let now = Utc::now().to_rfc3339();
        store
            .append(&ApiUsageInsert {
                session_id: "s1",
                agent_id: "a1",
                channel: "web",
                model: "claude-opus-4",
                provider: "anthropic",
                input_tokens: 1200,
                output_tokens: 340,
                total_tokens: 1540,
                iterations: 1,
                duration_ms: 850,
                started_at: &now,
                status: "completed",
                cost_usd: Some(0.01),
            })
            .unwrap();

        let (rows, agg) = store.query(&ApiUsageFilter::default(), 100).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session_id, "s1");
        assert_eq!(rows[0].model, "claude-opus-4");
        assert_eq!(rows[0].provider, "anthropic");
        assert_eq!(rows[0].input_tokens, 1200);
        assert_eq!(rows[0].output_tokens, 340);
        assert_eq!(rows[0].duration_ms, 850);

        assert_eq!(agg.row_count, 1);
        assert_eq!(agg.input_tokens, 1200);
        assert_eq!(agg.output_tokens, 340);
        assert_eq!(agg.total_tokens, 1540);
        assert_eq!(agg.total_duration_ms, 850);
    }

    #[test]
    fn filter_by_channel_excludes_other_rows() {
        let store = store();
        let now = Utc::now().to_rfc3339();
        for (ch, input) in [("web", 100u32), ("telegram", 200), ("cron", 300)] {
            store
                .append(&ApiUsageInsert {
                    session_id: "s1",
                    agent_id: "a1",
                    channel: ch,
                    model: "m",
                    provider: "p",
                    input_tokens: input,
                    output_tokens: 0,
                    total_tokens: input,
                    iterations: 1,
                    duration_ms: 100,
                    started_at: &now,
                    status: "completed",
                    cost_usd: None,
                })
                .unwrap();
        }

        let filter = ApiUsageFilter {
            channel: Some("telegram".to_string()),
            ..Default::default()
        };
        let (rows, agg) = store.query(&filter, 100).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].channel, "telegram");
        assert_eq!(agg.row_count, 1);
        assert_eq!(agg.input_tokens, 200);
    }

    #[test]
    fn aggregate_sums_ignore_page_limit() {
        let store = store();
        let now = Utc::now().to_rfc3339();
        for i in 0..5 {
            store
                .append(&ApiUsageInsert {
                    session_id: "s1",
                    agent_id: "a1",
                    channel: "web",
                    model: "m",
                    provider: "p",
                    input_tokens: 100,
                    output_tokens: 10,
                    total_tokens: 110,
                    iterations: 1,
                    duration_ms: 10,
                    started_at: &format!("{now}-{i}"),
                    status: "completed",
                    cost_usd: Some(0.005),
                })
                .unwrap();
        }

        // Limit page to 2 rows — aggregate must still cover all 5.
        let (rows, agg) = store.query(&ApiUsageFilter::default(), 2).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(agg.row_count, 5);
        assert_eq!(agg.input_tokens, 500);
        assert_eq!(agg.output_tokens, 50);
        assert_eq!(agg.total_tokens, 550);
    }

    #[test]
    fn filter_by_since_until_selects_window() {
        let store = store();
        for ts in [
            "2026-03-01T00:00:00Z",
            "2026-03-05T00:00:00Z",
            "2026-03-10T00:00:00Z",
        ] {
            store
                .append(&ApiUsageInsert {
                    session_id: "s",
                    agent_id: "a",
                    channel: "web",
                    model: "m",
                    provider: "p",
                    input_tokens: 1,
                    output_tokens: 0,
                    total_tokens: 1,
                    iterations: 1,
                    duration_ms: 1,
                    started_at: ts,
                    status: "completed",
                    cost_usd: None,
                })
                .unwrap();
        }

        let filter = ApiUsageFilter {
            since: Some("2026-03-03T00:00:00Z".to_string()),
            until: Some("2026-03-08T00:00:00Z".to_string()),
            ..Default::default()
        };
        let (rows, agg) = store.query(&filter, 100).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].started_at, "2026-03-05T00:00:00Z");
        assert_eq!(agg.row_count, 1);
    }

    #[test]
    fn filter_by_status_isolates_cancelled_rows() {
        // Persist a mix of completed, cancelled, and errored turns —
        // each with real token counts — and verify the status filter
        // returns only the requested class.
        let store = store();
        let now = Utc::now().to_rfc3339();
        for (status, input) in [
            ("completed", 1000u32),
            ("cancelled", 120),
            ("error", 50),
            ("completed", 2000),
            ("cancelled", 80),
        ] {
            store
                .append(&ApiUsageInsert {
                    session_id: "s",
                    agent_id: "a",
                    channel: "web",
                    model: "m",
                    provider: "p",
                    input_tokens: input,
                    output_tokens: 0,
                    total_tokens: input,
                    iterations: 1,
                    duration_ms: 10,
                    started_at: &now,
                    status,
                    cost_usd: None,
                })
                .unwrap();
        }

        let filter = ApiUsageFilter {
            status: Some("cancelled".to_string()),
            ..Default::default()
        };
        let (rows, agg) = store.query(&filter, 100).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.status == "cancelled"));
        assert_eq!(agg.row_count, 2);
        assert_eq!(agg.input_tokens, 200); // 120 + 80

        // Without the filter, all 5 rows are visible.
        let (all_rows, all_agg) = store.query(&ApiUsageFilter::default(), 100).unwrap();
        assert_eq!(all_rows.len(), 5);
        assert_eq!(all_agg.row_count, 5);
        assert_eq!(all_agg.input_tokens, 1000 + 120 + 50 + 2000 + 80);
    }

    #[test]
    fn default_status_on_insert_is_respected() {
        let store = store();
        let now = Utc::now().to_rfc3339();
        for status in ["completed", "cancelled", "error"] {
            store
                .append(&ApiUsageInsert {
                    session_id: "s",
                    agent_id: "a",
                    channel: "web",
                    model: "m",
                    provider: "p",
                    input_tokens: 10,
                    output_tokens: 0,
                    total_tokens: 10,
                    iterations: 1,
                    duration_ms: 1,
                    started_at: &now,
                    status,
                    cost_usd: None,
                })
                .unwrap();
        }
        let (rows, _) = store.query(&ApiUsageFilter::default(), 100).unwrap();
        assert_eq!(rows.len(), 3);
        // Verify every row preserved its assigned status.
        let mut statuses: Vec<String> = rows.iter().map(|r| r.status.clone()).collect();
        statuses.sort();
        assert_eq!(
            statuses,
            vec![
                "cancelled".to_string(),
                "completed".to_string(),
                "error".to_string()
            ]
        );
    }
}
