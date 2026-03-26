//! Event handling for PuzzlePod TUI.
//!
//! MPSC channel-based event system supporting terminal events, periodic ticks,
//! D-Bus signal events, and async action results.

use std::time::Duration;
use tokio::sync::mpsc;

/// Application events.
#[derive(Debug)]
#[allow(dead_code)]
pub enum AppEvent {
    /// Terminal input event (keyboard, mouse, resize).
    Terminal(crossterm::event::Event),
    /// Periodic tick for auto-refresh (2 seconds).
    Tick,
    /// Real-time D-Bus signal from puzzled.
    DbusSignal(DbusSignalEvent),
    /// Result of an async D-Bus action.
    ActionResult(ActionResult),
}

/// D-Bus signal events from the puzzled daemon.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum DbusSignalEvent {
    BranchCreated {
        branch_id: String,
        profile: String,
    },
    BranchCommitted {
        branch_id: String,
        changeset_hash: String,
        profile: String,
    },
    BranchRolledBack {
        branch_id: String,
        reason: String,
    },
    GovernanceReviewPending {
        branch_id: String,
        diff_summary: String,
    },
    PolicyViolation {
        branch_id: String,
        violations_json: String,
        reason: String,
        profile: String,
    },
    TrustTransition {
        uid: u32,
        old_level: String,
        new_level: String,
        score: u32,
        trigger_event: String,
    },
    BehavioralTrigger {
        branch_id: String,
        trigger_json: String,
    },
    AgentTimeout {
        branch_id: String,
        timeout_secs: u64,
    },
    CredentialRotated {
        branch_id: String,
        credential_name: String,
        expires_at: String,
    },
    CredentialResolved {
        branch_id: String,
        credential_name: String,
        domain: String,
    },
    CredentialProxyError {
        branch_id: String,
        error: String,
        domain: String,
    },
    DlpViolation {
        branch_id: String,
        rule_name: String,
        action: String,
        domain: String,
    },
    BranchEvent {
        branch_id: String,
        event_type: String,
        details_json: String,
    },
}

/// Result of an async D-Bus action.
#[derive(Debug)]
#[allow(dead_code)]
pub enum ActionResult {
    BranchesLoaded(Result<Vec<crate::tui::app::BranchInfo>, String>),
    BranchApproved {
        branch_id: String,
        result: Result<String, String>,
    },
    BranchRejected {
        branch_id: String,
        result: Result<bool, String>,
    },
    BranchCreated(Result<String, String>),
    BranchDeleted {
        branch_id: String,
        result: Result<bool, String>,
    },
    BranchInspected {
        branch_id: String,
        result: Result<String, String>,
    },
    BranchDiff {
        branch_id: String,
        result: Result<String, String>,
    },
    AuditEvents(Result<String, String>),
    CredentialsLoaded(Result<String, String>),
    CredentialStored(Result<bool, String>),
    CredentialRemoved(Result<bool, String>),
    CredentialRotated(Result<bool, String>),
    PolicyReloaded(Result<(bool, String), String>),
}

/// Event handler that manages terminal input, ticks, and D-Bus signals.
pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<AppEvent>,
    _terminal_task: tokio::task::JoinHandle<()>,
    _tick_task: tokio::task::JoinHandle<()>,
}

impl EventHandler {
    /// Create a new event handler with the given tick rate.
    /// Returns the handler and a sender for dispatching events from background tasks.
    pub fn new(tick_rate: Duration) -> (Self, mpsc::UnboundedSender<AppEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();

        let terminal_tx = tx.clone();
        let _terminal_task = tokio::spawn(async move {
            loop {
                match crossterm::event::poll(Duration::from_millis(50)) {
                    Ok(true) => {
                        if let Ok(evt) = crossterm::event::read() {
                            if terminal_tx.send(AppEvent::Terminal(evt)).is_err() {
                                break;
                            }
                        }
                    }
                    Ok(false) => {}
                    Err(_) => break,
                }
                // Yield to prevent busy-waiting
                tokio::task::yield_now().await;
            }
        });

        let tick_tx = tx.clone();
        let _tick_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tick_rate);
            loop {
                interval.tick().await;
                if tick_tx.send(AppEvent::Tick).is_err() {
                    break;
                }
            }
        });

        let handler = Self {
            rx,
            _terminal_task,
            _tick_task,
        };

        (handler, tx)
    }

    /// Wait for the next event.
    pub async fn next(&mut self) -> Option<AppEvent> {
        self.rx.recv().await
    }
}
