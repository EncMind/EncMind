use async_trait::async_trait;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::StorageError;
use encmind_core::traits::AgentRegistry;
use encmind_core::types::{AgentConfig, AgentId, SessionId};

/// SQLite-backed agent registry.
///
/// Follows the same pool-based pattern as `SqliteSessionStore`.
pub struct SqliteAgentRegistry {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteAgentRegistry {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AgentRegistry for SqliteAgentRegistry {
    async fn list_agents(&self) -> Result<Vec<AgentConfig>, StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, name, model, workspace, system_prompt, skills, is_default FROM agents ORDER BY id",
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .map_err(|e| StorageError::Sqlite(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let mut agents = Vec::with_capacity(rows.len());
        for (id, name, model, workspace, system_prompt, skills_json, is_default) in rows {
            let skills: Vec<String> = serde_json::from_str(&skills_json)
                .map_err(|e| StorageError::InvalidData(format!("invalid skills JSON: {e}")))?;
            agents.push(AgentConfig {
                id: AgentId::new(id),
                name,
                model,
                workspace,
                system_prompt,
                skills,
                is_default: is_default != 0,
            });
        }

        Ok(agents)
    }

    async fn get_agent(&self, id: &AgentId) -> Result<Option<AgentConfig>, StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let result = conn.query_row(
            "SELECT id, name, model, workspace, system_prompt, skills, is_default FROM agents WHERE id = ?1",
            rusqlite::params![id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        );

        match result {
            Ok((id, name, model, workspace, system_prompt, skills_json, is_default)) => {
                let skills: Vec<String> = serde_json::from_str(&skills_json)
                    .map_err(|e| StorageError::InvalidData(format!("invalid skills JSON: {e}")))?;
                Ok(Some(AgentConfig {
                    id: AgentId::new(id),
                    name,
                    model,
                    workspace,
                    system_prompt,
                    skills,
                    is_default: is_default != 0,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StorageError::Sqlite(e.to_string())),
        }
    }

    async fn resolve_agent(&self, session_id: &SessionId) -> Result<AgentId, StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let agent_id_str: String = conn
            .query_row(
                "SELECT agent_id FROM sessions WHERE id = ?1",
                rusqlite::params![session_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    StorageError::NotFound(format!("session {session_id}"))
                }
                other => StorageError::Sqlite(other.to_string()),
            })?;

        Ok(AgentId::new(agent_id_str))
    }

    async fn create_agent(&self, config: AgentConfig) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let skills_json = serde_json::to_string(&config.skills)
            .map_err(|e| StorageError::InvalidData(e.to_string()))?;

        conn.execute(
            "INSERT INTO agents (id, name, model, workspace, system_prompt, skills, is_default) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                config.id.as_str(),
                config.name,
                config.model,
                config.workspace,
                config.system_prompt,
                skills_json,
                config.is_default as i64,
            ],
        )
        .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        Ok(())
    }

    async fn update_agent(&self, id: &AgentId, config: AgentConfig) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let skills_json = serde_json::to_string(&config.skills)
            .map_err(|e| StorageError::InvalidData(e.to_string()))?;

        let rows = conn
            .execute(
                "UPDATE agents SET name = ?1, model = ?2, workspace = ?3, system_prompt = ?4, skills = ?5, is_default = ?6 WHERE id = ?7",
                rusqlite::params![
                    config.name,
                    config.model,
                    config.workspace,
                    config.system_prompt,
                    skills_json,
                    config.is_default as i64,
                    id.as_str(),
                ],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        if rows == 0 {
            return Err(StorageError::NotFound(format!("agent {id}")));
        }
        Ok(())
    }

    async fn delete_agent(&self, id: &AgentId) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let rows = conn
            .execute(
                "DELETE FROM agents WHERE id = ?1",
                rusqlite::params![id.as_str()],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        if rows == 0 {
            return Err(StorageError::NotFound(format!("agent {id}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_storage::migrations::run_migrations;
    use encmind_storage::pool::create_test_pool;

    fn setup() -> SqliteAgentRegistry {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        SqliteAgentRegistry::new(pool)
    }

    #[tokio::test]
    async fn list_agents_includes_default() {
        let reg = setup();
        let agents = reg.list_agents().await.unwrap();
        assert!(!agents.is_empty());
        assert!(agents.iter().any(|a| a.id.as_str() == "main"));
    }

    #[tokio::test]
    async fn get_default_agent() {
        let reg = setup();
        let agent = reg.get_agent(&AgentId::new("main")).await.unwrap().unwrap();
        assert_eq!(agent.name, "Main Assistant");
        assert!(agent.is_default);
    }

    #[tokio::test]
    async fn get_nonexistent_agent() {
        let reg = setup();
        let result = reg.get_agent(&AgentId::new("nonexistent")).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn create_and_get_agent() {
        let reg = setup();
        let config = AgentConfig {
            id: AgentId::new("researcher"),
            name: "Research Agent".into(),
            model: Some("claude-3-opus".into()),
            workspace: None,
            system_prompt: Some("You are a researcher.".into()),
            skills: vec!["web_search".into()],
            is_default: false,
        };
        reg.create_agent(config).await.unwrap();

        let agent = reg
            .get_agent(&AgentId::new("researcher"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.name, "Research Agent");
        assert_eq!(agent.model.as_deref(), Some("claude-3-opus"));
        assert_eq!(agent.skills, vec!["web_search"]);
    }

    #[tokio::test]
    async fn update_agent() {
        let reg = setup();
        let config = AgentConfig {
            id: AgentId::new("main"),
            name: "Updated Assistant".into(),
            model: Some("claude-4".into()),
            workspace: None,
            system_prompt: None,
            skills: vec!["code_run".into()],
            is_default: true,
        };
        reg.update_agent(&AgentId::new("main"), config)
            .await
            .unwrap();

        let agent = reg.get_agent(&AgentId::new("main")).await.unwrap().unwrap();
        assert_eq!(agent.name, "Updated Assistant");
        assert_eq!(agent.model.as_deref(), Some("claude-4"));
        assert_eq!(agent.skills, vec!["code_run"]);
    }

    #[tokio::test]
    async fn update_nonexistent_agent_errors() {
        let reg = setup();
        let config = AgentConfig {
            id: AgentId::new("ghost"),
            name: "Ghost".into(),
            model: None,
            workspace: None,
            system_prompt: None,
            skills: vec![],
            is_default: false,
        };
        let err = reg.update_agent(&AgentId::new("ghost"), config).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn delete_agent() {
        let reg = setup();
        // Create then delete
        let config = AgentConfig {
            id: AgentId::new("temp"),
            name: "Temp Agent".into(),
            model: None,
            workspace: None,
            system_prompt: None,
            skills: vec![],
            is_default: false,
        };
        reg.create_agent(config).await.unwrap();
        reg.delete_agent(&AgentId::new("temp")).await.unwrap();

        let result = reg.get_agent(&AgentId::new("temp")).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_agent_errors() {
        let reg = setup();
        let err = reg.delete_agent(&AgentId::new("ghost")).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn resolve_agent_for_session() {
        let reg = setup();
        // Create a session referencing 'main'
        let pool = &reg.pool;
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO sessions (id, channel, agent_id) VALUES ('s1', 'web', 'main')",
            [],
        )
        .unwrap();
        drop(conn);

        let agent_id = reg
            .resolve_agent(&SessionId::from_string("s1"))
            .await
            .unwrap();
        assert_eq!(agent_id.as_str(), "main");
    }

    #[tokio::test]
    async fn resolve_agent_missing_session_errors() {
        let reg = setup();
        let err = reg
            .resolve_agent(&SessionId::from_string("nonexistent"))
            .await;
        assert!(err.is_err());
    }
}
