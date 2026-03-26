//! Terminal UI for puzzlectl — interactive branch management.
//!
//! Provides a ratatui-based TUI with:
//! - Splash screen with ASCII art logo
//! - Dashboard: daemon status, credentials/settings tabs, branch table
//! - Branch detail: metadata sidebar + tabbed content (logs, diff, policy, settings)
//! - Governance review: approve/reject branches in GovernanceReview state
//! - Credential management: list, create, rotate, remove
//! - Real-time updates via D-Bus signal subscription
//! - Cyberpunk purple/magenta color theme
//!
//! Launch: `puzzlectl tui`

pub mod app;
pub mod clipboard;
pub mod event;
pub mod theme;
pub mod ui;

use anyhow::{Context, Result};
use crossterm::{
    event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::stdout;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::client::PuzzledClient;

use app::{
    App, BranchDetailTab, BranchInfo, ConfirmAction, ConfirmDialog, DashboardFocus, DashboardTab,
    DetailFocus, Screen,
};
use event::{ActionResult, AppEvent, EventHandler};
use theme::{NotificationLevel, Theme};

/// Run the TUI application.
pub async fn run_tui(bus_type: &str) -> Result<()> {
    // Detect theme before entering alternate screen
    let theme = Theme::detect();

    // Create event handler
    let (mut event_handler, event_tx) = EventHandler::new(Duration::from_secs(2));

    // Connect to D-Bus (graceful failure)
    let client = match PuzzledClient::connect(bus_type).await {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("Warning: could not connect to puzzled: {}", e);
            None
        }
    };

    // U28: Restore terminal on panic to prevent raw mode leak
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));

    // Set up terminal
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(theme, bus_type);

    // Set initial connection status
    if client.is_some() {
        app.daemon_status.connected = true;
        app.status_message = "Connected to puzzled".to_string();

        // Initial data load
        if let Some(ref c) = client {
            load_initial_data(&mut app, c).await;
        }
    } else {
        app.status_message = "Daemon not running — press [r] to retry".to_string();
    }

    // Spawn D-Bus signal listener if connected
    if let Some(ref c) = client {
        spawn_signal_listener(c, event_tx.clone());
    }

    // Main event loop
    loop {
        // Prune expired notifications
        app.prune_notifications();

        terminal.draw(|f| ui::draw(f, &mut app))?;

        match event_handler.next().await {
            Some(AppEvent::Terminal(Event::Key(key))) => {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                handle_key_event(&mut app, key, &client, &event_tx).await;
            }
            Some(AppEvent::Tick) => {
                handle_tick(&mut app, &client).await;
            }
            Some(AppEvent::DbusSignal(signal)) => {
                handle_dbus_signal(&mut app, signal);
            }
            Some(AppEvent::ActionResult(result)) => {
                handle_action_result(&mut app, result);
            }
            Some(AppEvent::Terminal(_)) => {}
            None => break,
        }

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    Ok(())
}

async fn load_initial_data(app: &mut App, client: &PuzzledClient) {
    match fetch_branches(client).await {
        Ok(branches) => {
            app.daemon_status.branch_count = branches.len();
            app.branches = branches;
            if !app.branches.is_empty() {
                app.branch_table_state.select(Some(0));
            }
            app.status_message = format!("{} branches loaded", app.branches.len());
        }
        Err(e) => {
            app.status_message = format!("Load failed: {}", e);
        }
    }

    // Try to load credentials
    if let Ok(creds_json) = client.list_credentials("").await {
        if let Ok(creds) = serde_json::from_str::<Vec<serde_json::Value>>(&creds_json) {
            app.credentials = creds;
        }
    }

    // Check policy status
    if let Ok((loaded, _)) = client.reload_policy().await {
        app.daemon_status.policy_loaded = loaded;
    }
}

// -- Key event handling --

async fn handle_key_event(
    app: &mut App,
    key: KeyEvent,
    client: &Option<PuzzledClient>,
    _event_tx: &mpsc::UnboundedSender<AppEvent>,
) {
    // Confirm dialog takes priority
    if app.confirm_dialog.is_some() {
        handle_confirm_key(app, key, client).await;
        return;
    }

    // Global keybindings
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    match &app.screen {
        Screen::Splash => handle_splash_key(app, key),
        Screen::Dashboard => handle_dashboard_key(app, key, client).await,
        Screen::BranchDetail(_) => handle_detail_key(app, key, client).await,
        Screen::CreateBranch => handle_create_branch_key(app, key, client).await,
        Screen::CreateCredential => handle_create_credential_key(app, key, client).await,
    }
}

fn handle_splash_key(app: &mut App, _key: KeyEvent) {
    app.screen = Screen::Dashboard;
}

async fn handle_dashboard_key(
    app: &mut App,
    key: KeyEvent,
    client: &Option<PuzzledClient>,
) {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            app.should_quit = true;
        }
        KeyCode::Tab => {
            app.cycle_dashboard_focus();
        }
        KeyCode::Down | KeyCode::Char('j') => match app.dashboard_focus {
            DashboardFocus::BranchTable => app.next_branch(),
            DashboardFocus::TabContent => {
                if app.dashboard_tab == DashboardTab::Credentials {
                    app.next_credential();
                }
            }
            _ => {}
        },
        KeyCode::Up | KeyCode::Char('k') => match app.dashboard_focus {
            DashboardFocus::BranchTable => app.previous_branch(),
            DashboardFocus::TabContent => {
                if app.dashboard_tab == DashboardTab::Credentials {
                    app.previous_credential();
                }
            }
            _ => {}
        },
        KeyCode::Enter => {
            if app.dashboard_focus == DashboardFocus::BranchTable {
                if let Some(branch) = app.selected_branch() {
                    let id = branch.id.0.clone();
                    app.detail_tab = BranchDetailTab::Logs;
                    app.detail_scroll = 0;
                    app.audit_scroll = 0;

                    // Load detail data
                    if let Some(c) = client {
                        load_branch_detail(app, c, &id).await;
                    }

                    app.screen = Screen::BranchDetail(id);
                }
            }
        }
        KeyCode::Char('c') => {
            if app.dashboard_focus == DashboardFocus::TabContent
                && app.dashboard_tab == DashboardTab::Credentials
            {
                app.reset_create_credential_form();
                app.screen = Screen::CreateCredential;
            } else {
                app.reset_create_branch_form();
                app.screen = Screen::CreateBranch;
            }
        }
        KeyCode::Char('d') => {
            if let Some(branch) = app.selected_branch() {
                let id = branch.id.0.clone();
                let short_id = &id[..id.len().min(12)];
                app.confirm_dialog = Some(ConfirmDialog {
                    title: "Delete Branch".to_string(),
                    message: format!("Rollback and delete branch {}?", short_id),
                    on_confirm: ConfirmAction::DeleteBranch(id),
                });
            }
        }
        KeyCode::Char('r') => {
            if let Some(c) = client {
                refresh_data(app, c).await;
            } else {
                app.status_message = "Not connected to daemon".to_string();
            }
        }
        KeyCode::Char('h') | KeyCode::Char('1') => {
            app.dashboard_tab = DashboardTab::Credentials;
        }
        KeyCode::Char('l') | KeyCode::Char('2') => {
            app.dashboard_tab = DashboardTab::Settings;
        }
        _ => {}
    }
}

async fn handle_detail_key(
    app: &mut App,
    key: KeyEvent,
    client: &Option<PuzzledClient>,
) {
    match key.code {
        KeyCode::Esc => {
            app.screen = Screen::Dashboard;
            app.detail_info = None;
            app.detail_diff.clear();
            app.audit_events.clear();
            app.policy_text.clear();
            app.detail_scroll = 0;
        }
        KeyCode::Tab => {
            app.detail_focus = match app.detail_focus {
                DetailFocus::Metadata => DetailFocus::Content,
                DetailFocus::Content => DetailFocus::Metadata,
            };
        }
        KeyCode::Char('h') => app.prev_detail_tab(),
        KeyCode::Char('l') => app.next_detail_tab(),
        KeyCode::Char('1') => app.detail_tab = BranchDetailTab::Logs,
        KeyCode::Char('2') => app.detail_tab = BranchDetailTab::DiffDraft,
        KeyCode::Char('3') => app.detail_tab = BranchDetailTab::Policy,
        KeyCode::Char('4') => app.detail_tab = BranchDetailTab::Settings,
        KeyCode::Down | KeyCode::Char('j') => {
            app.detail_scroll = app.detail_scroll.saturating_add(1);
            app.audit_scroll = app.audit_scroll.saturating_add(1);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.detail_scroll = app.detail_scroll.saturating_sub(1);
            app.audit_scroll = app.audit_scroll.saturating_sub(1);
        }
        KeyCode::Char('g') => {
            app.detail_scroll = 0;
            app.audit_scroll = 0;
        }
        KeyCode::Char('G') => {
            app.detail_scroll = u16::MAX;
            app.audit_scroll = u16::MAX;
        }
        KeyCode::Char('a') => {
            if let Screen::BranchDetail(ref id) = app.screen {
                let id = id.clone();
                if let Some(c) = client {
                    match c.approve_branch(&id).await {
                        Ok(result) => {
                            app.status_message = format!(
                                "Branch {} approved: {}",
                                &id[..id.len().min(8)],
                                result
                            );
                            app.notify(
                                format!("Branch {} approved", &id[..id.len().min(8)]),
                                NotificationLevel::Info,
                            );
                        }
                        Err(e) => {
                            app.status_message = format!("Approve failed: {}", e);
                        }
                    }
                }
            }
        }
        KeyCode::Char('x') => {
            if let Screen::BranchDetail(ref id) = app.screen {
                let id = id.clone();
                if let Some(c) = client {
                    // N6: Provide a meaningful reject reason
                    match c.reject_branch(&id, "rejected via TUI").await {
                        Ok(_) => {
                            app.status_message =
                                format!("Branch {} rejected", &id[..id.len().min(8)]);
                            app.notify(
                                format!("Branch {} rejected", &id[..id.len().min(8)]),
                                NotificationLevel::Warning,
                            );
                        }
                        Err(e) => {
                            app.status_message = format!("Reject failed: {}", e);
                        }
                    }
                }
            }
        }
        KeyCode::Char('i') => {
            if let Screen::BranchDetail(ref id) = app.screen {
                let id = id.clone();
                if let Some(c) = client {
                    load_branch_detail(app, c, &id).await;
                }
            }
        }
        KeyCode::Char('r') => {
            if let Screen::BranchDetail(ref id) = app.screen {
                let id = id.clone();
                if let Some(c) = client {
                    load_branch_detail(app, c, &id).await;
                    refresh_data(app, c).await;
                }
            }
        }
        KeyCode::Char('y') => {
            // Copy current detail to clipboard
            if let Some(ref info) = app.detail_info {
                let text = serde_json::to_string_pretty(info).unwrap_or_default();
                clipboard::copy_osc52(&text);
                app.status_message = "Copied to clipboard (OSC 52)".to_string();
            }
        }
        _ => {}
    }
}

async fn handle_create_branch_key(
    app: &mut App,
    key: KeyEvent,
    client: &Option<PuzzledClient>,
) {
    match key.code {
        KeyCode::Esc => {
            app.screen = Screen::Dashboard;
        }
        KeyCode::Tab => {
            app.create_branch_focus =
                (app.create_branch_focus + 1) % app.create_branch_fields.len();
        }
        KeyCode::BackTab => {
            if app.create_branch_focus == 0 {
                app.create_branch_focus = app.create_branch_fields.len() - 1;
            } else {
                app.create_branch_focus -= 1;
            }
        }
        KeyCode::Enter => {
            // Submit form
            let profile = app.create_branch_fields[0].effective_value().to_string();
            let base_path = app.create_branch_fields[1].value.clone();
            let command = app.create_branch_fields[2].value.clone();

            if let Some(c) = client {
                let cmd_json = if command.is_empty() {
                    "[]".to_string()
                } else {
                    command
                };
                let bp = if base_path.is_empty() {
                    "/tmp/puzzlepod"
                } else {
                    &base_path
                };

                match c.create_branch(&profile, bp, &cmd_json).await {
                    Ok(result) => {
                        app.status_message = format!("Branch created: {}", &result[..result.len().min(40)]);
                        app.notify("Branch created".to_string(), NotificationLevel::Info);
                        refresh_data(app, c).await;
                    }
                    Err(e) => {
                        app.status_message = format!("Create failed: {}", e);
                    }
                }
            }
            app.screen = Screen::Dashboard;
        }
        KeyCode::Char(c) => {
            if let Some(field) = app.create_branch_fields.get_mut(app.create_branch_focus) {
                if field.options.is_some() {
                    // Dropdown: j/k to cycle
                    if c == 'j' || c == 'k' {
                        if let Some(ref opts) = field.options {
                            let len = opts.len();
                            if c == 'j' {
                                field.selected_option = (field.selected_option + 1) % len;
                            } else {
                                field.selected_option = if field.selected_option == 0 {
                                    len - 1
                                } else {
                                    field.selected_option - 1
                                };
                            }
                        }
                    }
                } else {
                    field.value.push(c);
                }
            }
        }
        KeyCode::Backspace => {
            if let Some(field) = app.create_branch_fields.get_mut(app.create_branch_focus) {
                if field.options.is_none() {
                    field.value.pop();
                }
            }
        }
        _ => {}
    }
}

async fn handle_create_credential_key(
    app: &mut App,
    key: KeyEvent,
    client: &Option<PuzzledClient>,
) {
    match key.code {
        KeyCode::Esc => {
            app.screen = Screen::Dashboard;
        }
        KeyCode::Tab => {
            app.create_credential_focus =
                (app.create_credential_focus + 1) % app.create_credential_fields.len();
        }
        KeyCode::BackTab => {
            if app.create_credential_focus == 0 {
                app.create_credential_focus = app.create_credential_fields.len() - 1;
            } else {
                app.create_credential_focus -= 1;
            }
        }
        KeyCode::Enter => {
            let name = app.create_credential_fields[0].value.clone();
            let cred_type = app.create_credential_fields[1].effective_value().to_string();
            let value_source = app.create_credential_fields[2].value.clone();
            let config_json = app.create_credential_fields[3].value.clone();

            if let Some(c) = client {
                let cfg = if config_json.is_empty() {
                    "{}"
                } else {
                    &config_json
                };

                match c.store_credential(&name, &cred_type, &value_source, cfg).await {
                    Ok(_) => {
                        app.status_message = format!("Credential '{}' stored", name);
                        app.notify(
                            format!("Credential '{}' created", name),
                            NotificationLevel::Info,
                        );
                        // Refresh credentials
                        if let Ok(creds_json) = c.list_credentials("").await {
                            if let Ok(creds) =
                                serde_json::from_str::<Vec<serde_json::Value>>(&creds_json)
                            {
                                app.credentials = creds;
                            }
                        }
                    }
                    Err(e) => {
                        app.status_message = format!("Store credential failed: {}", e);
                    }
                }
            }
            app.screen = Screen::Dashboard;
        }
        KeyCode::Char(c) => {
            if let Some(field) = app
                .create_credential_fields
                .get_mut(app.create_credential_focus)
            {
                if field.options.is_some() {
                    if c == 'j' || c == 'k' {
                        if let Some(ref opts) = field.options {
                            let len = opts.len();
                            if c == 'j' {
                                field.selected_option = (field.selected_option + 1) % len;
                            } else {
                                field.selected_option = if field.selected_option == 0 {
                                    len - 1
                                } else {
                                    field.selected_option - 1
                                };
                            }
                        }
                    }
                } else {
                    field.value.push(c);
                }
            }
        }
        KeyCode::Backspace => {
            if let Some(field) = app
                .create_credential_fields
                .get_mut(app.create_credential_focus)
            {
                if field.options.is_none() {
                    field.value.pop();
                }
            }
        }
        _ => {}
    }
}

async fn handle_confirm_key(
    app: &mut App,
    key: KeyEvent,
    client: &Option<PuzzledClient>,
) {
    match key.code {
        KeyCode::Char('y') | KeyCode::Enter => {
            if let Some(dialog) = app.confirm_dialog.take() {
                match dialog.on_confirm {
                    ConfirmAction::DeleteBranch(id) => {
                        if let Some(c) = client {
                            match c.rollback_branch(&id, "deleted via TUI").await {
                                Ok(_) => {
                                    app.status_message =
                                        format!("Branch {} deleted", &id[..id.len().min(8)]);
                                    app.notify(
                                        format!("Branch {} deleted", &id[..id.len().min(8)]),
                                        NotificationLevel::Warning,
                                    );
                                    refresh_data(app, c).await;
                                }
                                Err(e) => {
                                    app.status_message = format!("Delete failed: {}", e);
                                }
                            }
                        }
                    }
                    ConfirmAction::RejectBranch(id) => {
                        if let Some(c) = client {
                            match c.reject_branch(&id, "rejected via TUI").await {
                                Ok(_) => {
                                    app.status_message =
                                        format!("Branch {} rejected", &id[..id.len().min(8)]);
                                }
                                Err(e) => {
                                    app.status_message = format!("Reject failed: {}", e);
                                }
                            }
                        }
                    }
                    ConfirmAction::RemoveCredential(name) => {
                        if let Some(c) = client {
                            match c.remove_credential(&name).await {
                                Ok(_) => {
                                    app.status_message =
                                        format!("Credential '{}' removed", name);
                                    if let Ok(creds_json) = c.list_credentials("").await {
                                        if let Ok(creds) = serde_json::from_str::<
                                            Vec<serde_json::Value>,
                                        >(
                                            &creds_json
                                        ) {
                                            app.credentials = creds;
                                        }
                                    }
                                }
                                Err(e) => {
                                    app.status_message =
                                        format!("Remove credential failed: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
        KeyCode::Char('n') | KeyCode::Esc => {
            app.confirm_dialog = None;
        }
        _ => {}
    }
}

// -- Tick handler --

async fn handle_tick(app: &mut App, client: &Option<PuzzledClient>) {
    // Auto-advance splash after 3 seconds
    if app.screen == Screen::Splash && app.splash_start.elapsed() > Duration::from_secs(3) {
        app.screen = Screen::Dashboard;
    }

    // Auto-refresh branch list on tick
    if app.screen == Screen::Dashboard {
        if let Some(c) = client {
            if let Ok(branches) = fetch_branches(c).await {
                let selected = app.branch_table_state.selected();
                app.daemon_status.branch_count = branches.len();
                app.branches = branches;
                // Preserve selection
                if let Some(idx) = selected {
                    if idx < app.branches.len() {
                        app.branch_table_state.select(Some(idx));
                    } else if !app.branches.is_empty() {
                        app.branch_table_state.select(Some(0));
                    }
                }
            }
        }
    }
}

// -- D-Bus signal handler --

fn handle_dbus_signal(app: &mut App, signal: event::DbusSignalEvent) {
    use event::DbusSignalEvent::*;
    match signal {
        BranchCreated {
            branch_id,
            profile,
        } => {
            app.notify(
                format!("Branch created: {} ({})", &branch_id[..branch_id.len().min(8)], profile),
                NotificationLevel::Info,
            );
        }
        BranchCommitted {
            branch_id,
            changeset_hash: _,
            profile: _,
        } => {
            app.notify(
                format!("Branch committed: {}", &branch_id[..branch_id.len().min(8)]),
                NotificationLevel::Info,
            );
        }
        BranchRolledBack {
            branch_id,
            reason,
        } => {
            app.notify(
                format!("Branch rolled back: {} ({})", &branch_id[..branch_id.len().min(8)], reason),
                NotificationLevel::Warning,
            );
        }
        GovernanceReviewPending {
            branch_id,
            diff_summary: _,
        } => {
            app.notify(
                format!("Review pending: {}", &branch_id[..branch_id.len().min(8)]),
                NotificationLevel::Warning,
            );
        }
        PolicyViolation {
            branch_id,
            reason,
            ..
        } => {
            app.notify(
                format!("Policy violation: {} — {}", &branch_id[..branch_id.len().min(8)], reason),
                NotificationLevel::Error,
            );
        }
        TrustTransition {
            uid,
            old_level,
            new_level,
            ..
        } => {
            app.notify(
                format!("Trust: uid {} {} -> {}", uid, old_level, new_level),
                NotificationLevel::Info,
            );
        }
        BehavioralTrigger {
            branch_id,
            trigger_json: _,
        } => {
            app.notify(
                format!("Behavioral trigger: {}", &branch_id[..branch_id.len().min(8)]),
                NotificationLevel::Warning,
            );
        }
        AgentTimeout {
            branch_id,
            timeout_secs,
        } => {
            app.notify(
                format!("Agent timeout: {} ({}s)", &branch_id[..branch_id.len().min(8)], timeout_secs),
                NotificationLevel::Warning,
            );
        }
        CredentialRotated {
            credential_name, ..
        } => {
            app.notify(
                format!("Credential rotated: {}", credential_name),
                NotificationLevel::Info,
            );
        }
        CredentialResolved {
            credential_name, ..
        } => {
            app.notify(
                format!("Credential resolved: {}", credential_name),
                NotificationLevel::Info,
            );
        }
        CredentialProxyError { error, domain, .. } => {
            app.notify(
                format!("Credential proxy error: {} ({})", error, domain),
                NotificationLevel::Error,
            );
        }
        DlpViolation {
            branch_id,
            rule_name,
            ..
        } => {
            app.notify(
                format!("DLP violation: {} — {}", &branch_id[..branch_id.len().min(8)], rule_name),
                NotificationLevel::Error,
            );
        }
        BranchEvent {
            branch_id,
            event_type,
            ..
        } => {
            app.notify(
                format!("{}: {}", event_type, &branch_id[..branch_id.len().min(8)]),
                NotificationLevel::Info,
            );
        }
    }
}

// -- Action result handler --

fn handle_action_result(app: &mut App, result: ActionResult) {
    match result {
        ActionResult::BranchesLoaded(Ok(branches)) => {
            app.daemon_status.branch_count = branches.len();
            app.branches = branches;
            app.status_message = format!("{} branches loaded", app.branches.len());
        }
        ActionResult::BranchesLoaded(Err(e)) => {
            app.status_message = format!("Load failed: {}", e);
        }
        _ => {} // Other results handled inline for now
    }
}

// -- Data loading helpers --

async fn fetch_branches(client: &PuzzledClient) -> Result<Vec<BranchInfo>> {
    let json = client.list_branches().await?;
    let branches: Vec<BranchInfo> =
        serde_json::from_str(&json).context("parsing branch list")?;
    Ok(branches)
}

async fn refresh_data(app: &mut App, client: &PuzzledClient) {
    match fetch_branches(client).await {
        Ok(branches) => {
            app.daemon_status.branch_count = branches.len();
            app.branches = branches;
            app.status_message = format!("{} branches refreshed", app.branches.len());
        }
        Err(e) => {
            app.status_message = format!("Refresh failed: {}", e);
        }
    }

    // Refresh credentials
    if let Ok(creds_json) = client.list_credentials("").await {
        if let Ok(creds) = serde_json::from_str::<Vec<serde_json::Value>>(&creds_json) {
            app.credentials = creds;
        }
    }
}

async fn load_branch_detail(app: &mut App, client: &PuzzledClient, branch_id: &str) {
    // Inspect
    match client.inspect_branch(branch_id).await {
        Ok(info) => {
            app.detail_info = serde_json::from_str(&info).ok();
            app.status_message = format!("Loaded detail for {}", &branch_id[..branch_id.len().min(8)]);
        }
        Err(e) => {
            app.status_message = format!("Inspect failed: {}", e);
        }
    }

    // Diff (non-critical)
    if let Ok(diff_json) = client.diff_branch(branch_id).await {
        if let Ok(diff) = serde_json::from_str::<Vec<serde_json::Value>>(&diff_json) {
            app.detail_diff = diff;
        }
    }

    // Audit events (non-critical)
    let filter = serde_json::json!({"branch_id": branch_id}).to_string();
    if let Ok(events_json) = client.query_audit_events(&filter).await {
        if let Ok(events) = serde_json::from_str::<Vec<serde_json::Value>>(&events_json) {
            app.audit_events = events;
        }
    }
}

// -- D-Bus signal listener --

fn spawn_signal_listener(
    client: &PuzzledClient,
    tx: mpsc::UnboundedSender<AppEvent>,
) {
    let connection = client.connection();

    tokio::spawn(async move {
        use zbus::MatchRule;

        let rule = match MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("org.lobstertrap.PuzzlePod1.Manager")
        {
            Ok(builder) => builder.build(),
            Err(_) => return,
        };

        // Try to add match rule — if it fails, signals won't work but TUI still runs
        if let Ok(mut stream) =
            zbus::MessageStream::for_match_rule(rule, connection, None).await
        {
            use futures_util::StreamExt;
            while let Some(result) = stream.next().await {
                if let Ok(msg) = result {
                    if let Some(signal_event) = parse_dbus_signal(&msg) {
                        if tx.send(AppEvent::DbusSignal(signal_event)).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
}

fn parse_dbus_signal(msg: &zbus::Message) -> Option<event::DbusSignalEvent> {
    let header = msg.header();
    let member = header.member()?.as_str();

    match member {
        "branch_created" => {
            let (branch_id, profile): (String, String) = msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::BranchCreated {
                branch_id,
                profile,
            })
        }
        "branch_committed" => {
            let (branch_id, changeset_hash, profile): (String, String, String) =
                msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::BranchCommitted {
                branch_id,
                changeset_hash,
                profile,
            })
        }
        "branch_rolled_back" => {
            let (branch_id, reason): (String, String) = msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::BranchRolledBack {
                branch_id,
                reason,
            })
        }
        "governance_review_pending" => {
            let (branch_id, diff_summary): (String, String) = msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::GovernanceReviewPending {
                branch_id,
                diff_summary,
            })
        }
        "policy_violation" => {
            let (branch_id, violations_json, _changeset_hash, reason, profile): (
                String,
                String,
                String,
                String,
                String,
            ) = msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::PolicyViolation {
                branch_id,
                violations_json,
                reason,
                profile,
            })
        }
        "trust_transition" => {
            let (uid, old_level, new_level, score, trigger_event): (
                u32,
                String,
                String,
                u32,
                String,
            ) = msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::TrustTransition {
                uid,
                old_level,
                new_level,
                score,
                trigger_event,
            })
        }
        "behavioral_trigger" => {
            let (branch_id, trigger_json): (String, String) = msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::BehavioralTrigger {
                branch_id,
                trigger_json,
            })
        }
        "agent_timeout" => {
            let (branch_id, timeout_secs): (String, u64) = msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::AgentTimeout {
                branch_id,
                timeout_secs,
            })
        }
        "credential_rotated" => {
            let (branch_id, credential_name, expires_at): (String, String, String) =
                msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::CredentialRotated {
                branch_id,
                credential_name,
                expires_at,
            })
        }
        "credential_resolved" => {
            let (branch_id, credential_name, domain, _timestamp): (
                String,
                String,
                String,
                String,
            ) = msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::CredentialResolved {
                branch_id,
                credential_name,
                domain,
            })
        }
        "credential_proxy_error" => {
            let (branch_id, error, domain): (String, String, String) =
                msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::CredentialProxyError {
                branch_id,
                error,
                domain,
            })
        }
        "dlp_violation" => {
            let (branch_id, rule_name, action, domain): (String, String, String, String) =
                msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::DlpViolation {
                branch_id,
                rule_name,
                action,
                domain,
            })
        }
        "branch_event" => {
            let (branch_id, event_type, details_json): (String, String, String) =
                msg.body().deserialize().ok()?;
            Some(event::DbusSignalEvent::BranchEvent {
                branch_id,
                event_type,
                details_json,
            })
        }
        _ => None,
    }
}
