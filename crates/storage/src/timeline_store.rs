use async_trait::async_trait;
use chrono::{DateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::StorageError;
use encmind_core::traits::TimelineStore;
use encmind_core::types::{
    AgentId, Pagination, SessionId, TimelineEvent, TimelineEventId, TimelineFilter,
};

pub struct SqliteTimelineStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteTimelineStore {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }
}

fn dt_to_string(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn row_to_event(row: &rusqlite::Row<'_>) -> Result<TimelineEvent, rusqlite::Error> {
    let id: String = row.get(0)?;
    let event_type: String = row.get(1)?;
    let source: String = row.get(2)?;
    let session_id: Option<String> = row.get(3)?;
    let agent_id: String = row.get(4)?;
    let summary: String = row.get(5)?;
    let detail: Option<String> = row.get(6)?;
    let created_at: String = row.get(7)?;

    let parsed_detail = match detail {
        Some(raw) => Some(serde_json::from_str(&raw).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
        })?),
        None => None,
    };

    let parsed_created_at = chrono::DateTime::parse_from_rfc3339(&created_at).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(TimelineEvent {
        id: TimelineEventId::from_string(id),
        event_type,
        source,
        session_id: session_id.map(SessionId::from_string),
        agent_id: AgentId::new(agent_id),
        summary,
        detail: parsed_detail,
        created_at: parsed_created_at.with_timezone(&Utc),
    })
}

#[async_trait]
impl TimelineStore for SqliteTimelineStore {
    async fn insert_event(&self, event: &TimelineEvent) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let event = event.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            conn.execute(
                "INSERT INTO timeline_events (id, event_type, source, session_id, agent_id, summary, detail, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    event.id.as_str(),
                    event.event_type,
                    event.source,
                    event.session_id.as_ref().map(|s| s.as_str().to_owned()),
                    event.agent_id.as_str(),
                    event.summary,
                    event.detail.as_ref().map(|d| serde_json::to_string(d).unwrap_or_default()),
                    dt_to_string(&event.created_at),
                ],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn query_events(
        &self,
        filter: &TimelineFilter,
        pagination: &Pagination,
    ) -> Result<Vec<TimelineEvent>, StorageError> {
        let pool = self.pool.clone();
        let filter = filter.clone();
        let limit = pagination.limit as i64;
        let offset = pagination.offset as i64;
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;

            let mut sql = String::from(
                "SELECT id, event_type, source, session_id, agent_id, summary, detail, created_at \
                 FROM timeline_events WHERE 1=1",
            );
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

            if let Some(ref et) = filter.event_type {
                params.push(Box::new(et.clone()));
                sql.push_str(&format!(" AND event_type = ?{}", params.len()));
            }
            if let Some(ref src) = filter.source {
                params.push(Box::new(src.clone()));
                sql.push_str(&format!(" AND source = ?{}", params.len()));
            }
            if let Some(ref aid) = filter.agent_id {
                params.push(Box::new(aid.as_str().to_owned()));
                sql.push_str(&format!(" AND agent_id = ?{}", params.len()));
            }
            if let Some(ref since) = filter.since {
                params.push(Box::new(dt_to_string(since)));
                sql.push_str(&format!(" AND created_at >= ?{}", params.len()));
            }
            if let Some(ref until) = filter.until {
                params.push(Box::new(dt_to_string(until)));
                sql.push_str(&format!(" AND created_at <= ?{}", params.len()));
            }

            sql.push_str(" ORDER BY created_at DESC");
            params.push(Box::new(limit));
            sql.push_str(&format!(" LIMIT ?{}", params.len()));
            params.push(Box::new(offset));
            sql.push_str(&format!(" OFFSET ?{}", params.len()));

            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();

            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let events = stmt
                .query_map(param_refs.as_slice(), row_to_event)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;

            Ok(events)
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::run_migrations;
    use crate::pool::create_test_pool;

    fn make_store() -> SqliteTimelineStore {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        SqliteTimelineStore::new(pool)
    }

    fn make_event(event_type: &str, source: &str, summary: &str) -> TimelineEvent {
        TimelineEvent {
            id: TimelineEventId::new(),
            event_type: event_type.into(),
            source: source.into(),
            session_id: None,
            agent_id: AgentId::default(),
            summary: summary.into(),
            detail: None,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn insert_and_query_roundtrip() {
        let store = make_store();
        let event = make_event("message", "web", "User sent a message");
        store.insert_event(&event).await.unwrap();

        let events = store
            .query_events(&TimelineFilter::default(), &Pagination::default())
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
        assert_eq!(events[0].summary, "User sent a message");
    }

    #[tokio::test]
    async fn query_filters_by_event_type() {
        let store = make_store();
        store
            .insert_event(&make_event("message", "web", "msg"))
            .await
            .unwrap();
        store
            .insert_event(&make_event("cron_run", "cron", "cron job ran"))
            .await
            .unwrap();

        let filter = TimelineFilter {
            event_type: Some("cron_run".into()),
            ..Default::default()
        };
        let events = store
            .query_events(&filter, &Pagination::default())
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "cron_run");
    }

    #[tokio::test]
    async fn query_filters_by_source() {
        let store = make_store();
        store
            .insert_event(&make_event("message", "telegram", "tg msg"))
            .await
            .unwrap();
        store
            .insert_event(&make_event("message", "web", "web msg"))
            .await
            .unwrap();

        let filter = TimelineFilter {
            source: Some("telegram".into()),
            ..Default::default()
        };
        let events = store
            .query_events(&filter, &Pagination::default())
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, "telegram");
    }

    #[tokio::test]
    async fn query_respects_pagination() {
        let store = make_store();
        for i in 0..5 {
            store
                .insert_event(&make_event("message", "web", &format!("msg-{i}")))
                .await
                .unwrap();
        }

        let page = store
            .query_events(
                &TimelineFilter::default(),
                &Pagination {
                    offset: 0,
                    limit: 2,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
    }

    #[tokio::test]
    async fn insert_with_detail_json() {
        let store = make_store();
        let mut event = make_event("tool_use", "web", "Ran bash command");
        event.detail = Some(serde_json::json!({"tool": "bash", "exit_code": 0}));
        store.insert_event(&event).await.unwrap();

        let events = store
            .query_events(&TimelineFilter::default(), &Pagination::default())
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        let detail = events[0].detail.as_ref().unwrap();
        assert_eq!(detail["tool"], "bash");
    }

    #[tokio::test]
    async fn query_fails_on_invalid_detail_json() {
        let store = make_store();
        {
            let conn = store.pool.get().unwrap();
            conn.execute(
                "INSERT INTO timeline_events (id, event_type, source, session_id, agent_id, summary, detail, created_at)
                 VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    TimelineEventId::new().as_str(),
                    "message",
                    "web",
                    AgentId::default().as_str(),
                    "bad detail",
                    "{invalid-json",
                    "2026-01-01T00:00:00Z",
                ],
            )
            .unwrap();
        }

        let err = store
            .query_events(&TimelineFilter::default(), &Pagination::default())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("Conversion error from type Text at index: 6"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn query_fails_on_invalid_created_at() {
        let store = make_store();
        {
            let conn = store.pool.get().unwrap();
            conn.execute(
                "INSERT INTO timeline_events (id, event_type, source, session_id, agent_id, summary, detail, created_at)
                 VALUES (?1, ?2, ?3, NULL, ?4, ?5, NULL, ?6)",
                rusqlite::params![
                    TimelineEventId::new().as_str(),
                    "message",
                    "web",
                    AgentId::default().as_str(),
                    "bad time",
                    "not-a-timestamp",
                ],
            )
            .unwrap();
        }

        let err = store
            .query_events(&TimelineFilter::default(), &Pagination::default())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("Conversion error from type Text at index: 7"),
            "unexpected error: {err}"
        );
    }
}
