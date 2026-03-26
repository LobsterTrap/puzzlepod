//! Application state for PuzzlePod TUI.
//!
//! Centralizes all TUI state: screens, navigation, branch data, form state,
//! notifications, and daemon connection status.

use ratatui::widgets::{ListState, TableState};
use std::time::Instant;

use super::theme::{NotificationLevel, Theme};

// -- Data types parsed from D-Bus JSON --

/// Branch info parsed from D-Bus JSON response.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BranchInfo {
    pub id: BranchIdWrapper,
    pub profile: String,
    pub state: String,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub base_path: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub selinux_context: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BranchIdWrapper(pub String);

// -- Screen and navigation enums --

/// Active screen in the TUI.
#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    Splash,
    Dashboard,
    BranchDetail(String),
    CreateBranch,
    CreateCredential,
    AuditLog,
}

/// Dashboard data mode: live D-Bus polling or historical audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardMode {
    Live,
    Log,
}

/// Dashboard tab selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardTab {
    Credentials,
    Settings,
}

/// Branch detail tab selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchDetailTab {
    Logs,
    DiffDraft,
    Policy,
    Settings,
}

/// Which pane has input focus on the dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardFocus {
    DaemonStatus,
    TabContent,
    BranchTable,
}

/// Which pane has input focus on the branch detail view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailFocus {
    Metadata,
    Content,
}

// -- Form types --

/// A field in a modal form.
#[derive(Debug, Clone)]
pub struct FormField {
    pub label: String,
    pub value: String,
    /// If set, this is a dropdown/select field.
    pub options: Option<Vec<String>>,
    pub selected_option: usize,
}

impl FormField {
    pub fn text(label: &str) -> Self {
        Self {
            label: label.to_string(),
            value: String::new(),
            options: None,
            selected_option: 0,
        }
    }

    pub fn select(label: &str, options: Vec<String>) -> Self {
        Self {
            label: label.to_string(),
            value: options.first().cloned().unwrap_or_default(),
            options: Some(options),
            selected_option: 0,
        }
    }

    /// Get the effective value (selected option or text input).
    pub fn effective_value(&self) -> &str {
        if let Some(opts) = &self.options {
            opts.get(self.selected_option).map(|s| s.as_str()).unwrap_or("")
        } else {
            &self.value
        }
    }
}

// -- Notification --

/// A timed notification toast.
#[derive(Debug, Clone)]
pub struct Notification {
    pub message: String,
    pub level: NotificationLevel,
    pub created: Instant,
}

impl Notification {
    pub fn new(message: String, level: NotificationLevel) -> Self {
        Self {
            message,
            level,
            created: Instant::now(),
        }
    }

    /// Whether this notification has expired (3 seconds).
    pub fn is_expired(&self) -> bool {
        self.created.elapsed() > std::time::Duration::from_secs(3)
    }
}

// -- Daemon status --

/// Connection status of the puzzled daemon.
#[derive(Debug, Clone)]
pub struct DaemonStatus {
    pub connected: bool,
    pub bus_type: String,
    pub branch_count: usize,
    pub policy_loaded: bool,
}

impl DaemonStatus {
    pub fn new(bus_type: &str) -> Self {
        Self {
            connected: false,
            bus_type: bus_type.to_string(),
            branch_count: 0,
            policy_loaded: false,
        }
    }
}

// -- Confirmation dialog --

/// A confirmation dialog state.
#[derive(Debug, Clone)]
pub struct ConfirmDialog {
    pub title: String,
    pub message: String,
    pub on_confirm: ConfirmAction,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ConfirmAction {
    DeleteBranch(String),
    RejectBranch(String),
    RemoveCredential(String),
}

// -- Main App state --

/// TUI application state.
pub struct App {
    pub screen: Screen,
    pub theme: Theme,
    pub should_quit: bool,
    pub status_message: String,

    // Dashboard state
    pub dashboard_mode: DashboardMode,
    pub dashboard_focus: DashboardFocus,
    pub dashboard_tab: DashboardTab,
    pub branches: Vec<BranchInfo>,
    pub branch_table_state: TableState,
    pub daemon_status: DaemonStatus,

    // Credentials (dashboard tab)
    pub credentials: Vec<serde_json::Value>,
    pub credential_list_state: ListState,

    // Branch detail state
    pub detail_tab: BranchDetailTab,
    pub detail_focus: DetailFocus,
    pub detail_info: Option<serde_json::Value>,
    pub detail_diff: Vec<serde_json::Value>,
    pub audit_events: Vec<serde_json::Value>,
    pub audit_scroll: u16,
    pub policy_text: String,
    pub detail_scroll: u16,

    // Create branch form
    pub create_branch_fields: Vec<FormField>,
    pub create_branch_focus: usize,

    // Create credential form
    pub create_credential_fields: Vec<FormField>,
    pub create_credential_focus: usize,

    // Confirm dialog
    pub confirm_dialog: Option<ConfirmDialog>,

    // Notifications
    pub notifications: Vec<Notification>,

    // Splash timing
    pub splash_start: Instant,

    // Audit log mode state
    pub audit_log_events: Vec<serde_json::Value>,
    pub audit_log_scroll: u16,
    pub audit_log_filter_branch: String,
    pub audit_log_filter_type: String,
    pub audit_log_filter_focus: usize,

    // Reject reason input (future: interactive input)
    #[allow(dead_code)]
    pub reject_reason_input: Option<String>,
}

impl App {
    pub fn new(theme: Theme, bus_type: &str) -> Self {
        Self {
            screen: Screen::Splash,
            theme,
            should_quit: false,
            status_message: String::new(),

            dashboard_mode: DashboardMode::Live,
            dashboard_focus: DashboardFocus::BranchTable,
            dashboard_tab: DashboardTab::Credentials,
            branches: Vec::new(),
            branch_table_state: TableState::default(),
            daemon_status: DaemonStatus::new(bus_type),

            credentials: Vec::new(),
            credential_list_state: ListState::default(),

            detail_tab: BranchDetailTab::Logs,
            detail_focus: DetailFocus::Content,
            detail_info: None,
            detail_diff: Vec::new(),
            audit_events: Vec::new(),
            audit_scroll: 0,
            policy_text: String::new(),
            detail_scroll: 0,

            create_branch_fields: Self::default_create_branch_fields(),
            create_branch_focus: 0,

            create_credential_fields: Self::default_create_credential_fields(),
            create_credential_focus: 0,

            confirm_dialog: None,
            notifications: Vec::new(),
            splash_start: Instant::now(),

            audit_log_events: Vec::new(),
            audit_log_scroll: 0,
            audit_log_filter_branch: String::new(),
            audit_log_filter_type: String::new(),
            audit_log_filter_focus: 0,

            reject_reason_input: None,
        }
    }

    fn default_create_branch_fields() -> Vec<FormField> {
        vec![
            FormField::select(
                "Profile",
                vec![
                    "restricted".to_string(),
                    "standard".to_string(),
                    "privileged".to_string(),
                ],
            ),
            FormField::text("Base Path"),
            FormField::text("Command (JSON)"),
        ]
    }

    fn default_create_credential_fields() -> Vec<FormField> {
        vec![
            FormField::text("Name"),
            FormField::select(
                "Type",
                vec![
                    "api_key".to_string(),
                    "env_var".to_string(),
                    "file".to_string(),
                ],
            ),
            FormField::text("Value Source"),
            FormField::text("Config JSON"),
        ]
    }

    // -- Navigation --

    pub fn next_branch(&mut self) {
        let len = self.branches.len();
        if len == 0 {
            return;
        }
        let i = match self.branch_table_state.selected() {
            Some(i) => (i + 1) % len,
            None => 0,
        };
        self.branch_table_state.select(Some(i));
    }

    pub fn previous_branch(&mut self) {
        let len = self.branches.len();
        if len == 0 {
            return;
        }
        let i = match self.branch_table_state.selected() {
            Some(i) => {
                if i == 0 {
                    len - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.branch_table_state.select(Some(i));
    }

    pub fn selected_branch(&self) -> Option<&BranchInfo> {
        self.branch_table_state
            .selected()
            .and_then(|i| self.branches.get(i))
    }

    /// Cycle dashboard focus: DaemonStatus -> TabContent -> BranchTable.
    pub fn cycle_dashboard_focus(&mut self) {
        self.dashboard_focus = match self.dashboard_focus {
            DashboardFocus::DaemonStatus => DashboardFocus::TabContent,
            DashboardFocus::TabContent => DashboardFocus::BranchTable,
            DashboardFocus::BranchTable => DashboardFocus::DaemonStatus,
        };
    }

    /// Cycle detail tabs.
    pub fn next_detail_tab(&mut self) {
        self.detail_tab = match self.detail_tab {
            BranchDetailTab::Logs => BranchDetailTab::DiffDraft,
            BranchDetailTab::DiffDraft => BranchDetailTab::Policy,
            BranchDetailTab::Policy => BranchDetailTab::Settings,
            BranchDetailTab::Settings => BranchDetailTab::Logs,
        };
    }

    pub fn prev_detail_tab(&mut self) {
        self.detail_tab = match self.detail_tab {
            BranchDetailTab::Logs => BranchDetailTab::Settings,
            BranchDetailTab::DiffDraft => BranchDetailTab::Logs,
            BranchDetailTab::Policy => BranchDetailTab::DiffDraft,
            BranchDetailTab::Settings => BranchDetailTab::Policy,
        };
    }

    /// Navigate items in the currently focused credential list.
    pub fn next_credential(&mut self) {
        let len = self.credentials.len();
        if len == 0 {
            return;
        }
        let i = match self.credential_list_state.selected() {
            Some(i) => (i + 1) % len,
            None => 0,
        };
        self.credential_list_state.select(Some(i));
    }

    pub fn previous_credential(&mut self) {
        let len = self.credentials.len();
        if len == 0 {
            return;
        }
        let i = match self.credential_list_state.selected() {
            Some(i) => {
                if i == 0 {
                    len - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.credential_list_state.select(Some(i));
    }

    /// Add a notification toast.
    pub fn notify(&mut self, message: String, level: NotificationLevel) {
        self.notifications.push(Notification::new(message, level));
    }

    /// Remove expired notifications.
    pub fn prune_notifications(&mut self) {
        self.notifications.retain(|n| !n.is_expired());
    }

    /// Reset create-branch form to defaults.
    pub fn reset_create_branch_form(&mut self) {
        self.create_branch_fields = Self::default_create_branch_fields();
        self.create_branch_focus = 0;
    }

    /// Reset create-credential form to defaults.
    pub fn reset_create_credential_form(&mut self) {
        self.create_credential_fields = Self::default_create_credential_fields();
        self.create_credential_focus = 0;
    }
}

/// Pretty-format a JSON string.
#[allow(dead_code)]
pub fn format_json_pretty(json: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| json.to_string()),
        Err(_) => json.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_branch(id: &str, state: &str) -> BranchInfo {
        BranchInfo {
            id: BranchIdWrapper(id.to_string()),
            profile: "test".to_string(),
            state: state.to_string(),
            pid: Some(123),
            uid: 1000,
            base_path: None,
            created_at: None,
            expires_at: None,
            selinux_context: None,
        }
    }

    #[test]
    fn test_app_new() {
        let app = App::new(Theme::dark(), "session");
        assert!(app.branches.is_empty());
        assert!(!app.should_quit);
        assert_eq!(app.screen, Screen::Splash);
    }

    #[test]
    fn test_app_next_empty() {
        let mut app = App::new(Theme::dark(), "session");
        app.next_branch();
        assert_eq!(app.branch_table_state.selected(), None);
    }

    #[test]
    fn test_app_previous_empty() {
        let mut app = App::new(Theme::dark(), "session");
        app.previous_branch();
        assert_eq!(app.branch_table_state.selected(), None);
    }

    #[test]
    fn test_app_next_wraps() {
        let mut app = App::new(Theme::dark(), "session");
        app.branches = vec![
            make_test_branch("aaa", "active"),
            make_test_branch("bbb", "frozen"),
        ];
        app.branch_table_state.select(Some(1));
        app.next_branch();
        assert_eq!(app.branch_table_state.selected(), Some(0));
    }

    #[test]
    fn test_app_previous_wraps() {
        let mut app = App::new(Theme::dark(), "session");
        app.branches = vec![
            make_test_branch("aaa", "active"),
            make_test_branch("bbb", "frozen"),
        ];
        app.branch_table_state.select(Some(0));
        app.previous_branch();
        assert_eq!(app.branch_table_state.selected(), Some(1));
    }

    #[test]
    fn test_app_selected_branch() {
        let mut app = App::new(Theme::dark(), "session");
        assert!(app.selected_branch().is_none());

        app.branches = vec![make_test_branch("test-id", "active")];
        app.branch_table_state.select(Some(0));
        let branch = app.selected_branch().unwrap();
        assert_eq!(branch.id.0, "test-id");
        assert_eq!(branch.profile, "test");
    }

    #[test]
    fn test_format_json_pretty_valid() {
        let result = format_json_pretty(r#"{"a":1,"b":2}"#);
        assert!(result.contains("\"a\": 1"));
        assert!(result.contains("\"b\": 2"));
    }

    #[test]
    fn test_format_json_pretty_invalid() {
        let result = format_json_pretty("not json at all");
        assert_eq!(result, "not json at all");
    }

    #[test]
    fn test_branch_info_deserialize() {
        let json =
            r#"{"id":"abc123","profile":"standard","state":"active","pid":42,"uid":1000}"#;
        let info: BranchInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.id.0, "abc123");
        assert_eq!(info.profile, "standard");
        assert_eq!(info.state, "active");
        assert_eq!(info.pid, Some(42));
        assert_eq!(info.uid, 1000);
    }

    #[test]
    fn test_branch_info_deserialize_no_pid() {
        let json = r#"{"id":"abc123","profile":"standard","state":"active","pid":null,"uid":1000}"#;
        let info: BranchInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.pid, None);
    }

    #[test]
    fn test_cycle_dashboard_focus() {
        let mut app = App::new(Theme::dark(), "session");
        app.dashboard_focus = DashboardFocus::DaemonStatus;
        app.cycle_dashboard_focus();
        assert_eq!(app.dashboard_focus, DashboardFocus::TabContent);
        app.cycle_dashboard_focus();
        assert_eq!(app.dashboard_focus, DashboardFocus::BranchTable);
        app.cycle_dashboard_focus();
        assert_eq!(app.dashboard_focus, DashboardFocus::DaemonStatus);
    }

    #[test]
    fn test_notification_expiry() {
        let n = Notification::new("test".to_string(), NotificationLevel::Info);
        assert!(!n.is_expired());
    }

    #[test]
    fn test_form_field_text() {
        let f = FormField::text("Name");
        assert_eq!(f.label, "Name");
        assert_eq!(f.effective_value(), "");
    }

    #[test]
    fn test_form_field_select() {
        let f = FormField::select("Profile", vec!["a".to_string(), "b".to_string()]);
        assert_eq!(f.effective_value(), "a");
    }
}
