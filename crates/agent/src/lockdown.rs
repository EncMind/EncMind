use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use encmind_core::config::LockdownConfig;
use encmind_storage::audit::AuditLogger;
use serde::{Deserialize, Serialize};

/// Manages lockdown state for the assistant. When active, all external
/// operations are blocked. Uses an atomic bool for fast `is_active()` checks.
pub struct LockdownManager {
    active: Arc<AtomicBool>,
    config: LockdownConfig,
    audit: Option<Arc<AuditLogger>>,
}

/// Serializable lockdown state for persistence in `app_config`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockdownState {
    pub active: bool,
    pub reason: Option<String>,
}

impl LockdownManager {
    pub fn new(config: &LockdownConfig) -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            config: config.clone(),
            audit: None,
        }
    }

    pub fn with_audit(mut self, audit: Arc<AuditLogger>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Fast check: is lockdown currently active?
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Activate lockdown mode.
    pub fn activate(&self, reason: &str) {
        self.active.store(true, Ordering::SeqCst);
        if let Some(ref audit) = self.audit {
            let _ = audit.append(
                "security.lockdown",
                "activated",
                Some(reason),
                Some("lockdown_manager"),
            );
        }
    }

    /// Deactivate lockdown mode.
    pub fn deactivate(&self) {
        self.active.store(false, Ordering::SeqCst);
        if let Some(ref audit) = self.audit {
            let _ = audit.append(
                "security.lockdown",
                "deactivated",
                None,
                Some("lockdown_manager"),
            );
        }
    }

    /// Check if a trigger should cause auto-lockdown.
    pub fn should_auto_lockdown(&self, trigger: &str) -> bool {
        self.config
            .auto_lockdown_triggers
            .iter()
            .any(|t| t == trigger)
    }

    /// Get the current serializable state.
    pub fn state(&self) -> LockdownState {
        LockdownState {
            active: self.is_active(),
            reason: None,
        }
    }

    /// Restore lockdown state from a previously persisted state.
    pub fn restore(&self, state: &LockdownState) {
        self.active.store(state.active, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_storage::migrations::run_migrations;
    use encmind_storage::pool::create_test_pool;

    fn default_config() -> LockdownConfig {
        LockdownConfig {
            persist_across_restarts: true,
            auto_lockdown_triggers: vec!["attestation_failure".into()],
        }
    }

    #[test]
    fn new_not_active() {
        let mgr = LockdownManager::new(&default_config());
        assert!(!mgr.is_active());
    }

    #[test]
    fn activate_and_deactivate() {
        let mgr = LockdownManager::new(&default_config());
        mgr.activate("test");
        assert!(mgr.is_active());
        mgr.deactivate();
        assert!(!mgr.is_active());
    }

    #[test]
    fn atomic_check_across_clones() {
        let mgr = LockdownManager::new(&default_config());
        let active_flag = mgr.active.clone();
        mgr.activate("test");
        assert!(active_flag.load(Ordering::Relaxed));
    }

    #[test]
    fn auto_lockdown_trigger_match() {
        let mgr = LockdownManager::new(&default_config());
        assert!(mgr.should_auto_lockdown("attestation_failure"));
    }

    #[test]
    fn auto_lockdown_trigger_no_match() {
        let mgr = LockdownManager::new(&default_config());
        assert!(!mgr.should_auto_lockdown("something_else"));
    }

    #[test]
    fn state_roundtrip() {
        let mgr = LockdownManager::new(&default_config());
        mgr.activate("test");
        let state = mgr.state();
        assert!(state.active);

        let json = serde_json::to_string(&state).unwrap();
        let state2: LockdownState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, state2);
    }

    #[test]
    fn restore_active() {
        let mgr = LockdownManager::new(&default_config());
        let state = LockdownState {
            active: true,
            reason: Some("restored".into()),
        };
        mgr.restore(&state);
        assert!(mgr.is_active());
    }

    #[test]
    fn restore_inactive() {
        let mgr = LockdownManager::new(&default_config());
        mgr.activate("test");
        let state = LockdownState {
            active: false,
            reason: None,
        };
        mgr.restore(&state);
        assert!(!mgr.is_active());
    }

    #[test]
    fn audit_on_activate() {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        let audit = Arc::new(AuditLogger::new(pool));
        let mgr = LockdownManager::new(&default_config()).with_audit(audit.clone());

        mgr.activate("test reason");

        let entries = audit
            .query(
                encmind_storage::audit::AuditFilter {
                    category: Some("security.lockdown".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "activated");
        assert_eq!(entries[0].detail.as_deref(), Some("test reason"));
    }

    #[test]
    fn audit_on_deactivate() {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        let audit = Arc::new(AuditLogger::new(pool));
        let mgr = LockdownManager::new(&default_config()).with_audit(audit.clone());

        mgr.activate("reason");
        mgr.deactivate();

        let entries = audit
            .query(
                encmind_storage::audit::AuditFilter {
                    category: Some("security.lockdown".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(entries.len(), 2);
    }
}
