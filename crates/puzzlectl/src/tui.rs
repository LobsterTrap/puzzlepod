// SPDX-License-Identifier: Apache-2.0
//! Terminal UI for puzzlectl — interactive branch management.
//!
//! Provides a ratatui-based TUI with:
//! - Branch list panel (left) with state color coding
//! - Diff/detail panel (right) with colored file changes
//! - Actions bar: [a]pprove [r]eject [i]nspect [q]uit
//! - Real-time updates via D-Bus signal subscription
//!
//! Launch: `puzzlectl tui`

use anyhow::{Context, Result};

use crossterm::ExecutableCommand;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use std::io::stdout;

use crate::client::PuzzledClient;

/// Branch info parsed from D-Bus JSON response.
#[derive(Debug, Clone, serde::Deserialize)]
struct BranchInfo {
    id: BranchIdWrapper,
    profile: String,
    state: String,
    pid: Option<u32>,
    uid: u32,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BranchIdWrapper(String);

/// TUI application state.
struct App {
    branches: Vec<BranchInfo>,
    list_state: ListState,
    detail_text: String,
    status_message: String,
    should_quit: bool,
}

impl App {
    fn new() -> Self {
        Self {
            branches: Vec::new(),
            list_state: ListState::default(),
            detail_text: String::new(),
            status_message: "Press [r]efresh to load branches".to_string(),
            should_quit: false,
        }
    }

    fn next(&mut self) {
        let len = self.branches.len();
        if len == 0 {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => (i + 1) % len,
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn previous(&mut self) {
        let len = self.branches.len();
        if len == 0 {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    len - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn selected_branch(&self) -> Option<&BranchInfo> {
        self.list_state
            .selected()
            .and_then(|i| self.branches.get(i))
    }
}

/// Run the TUI application.
pub async fn run_tui(bus_type: &str) -> Result<()> {
    let client = PuzzledClient::connect(bus_type).await?;

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

    let mut app = App::new();

    // Initial load
    if let Ok(branches) = fetch_branches(&client).await {
        app.branches = branches;
        if !app.branches.is_empty() {
            app.list_state.select(Some(0));
        }
        app.status_message = format!("{} branches loaded", app.branches.len());
    }

    // Main loop
    loop {
        terminal.draw(|f| draw_ui(f, &mut app))?;

        if event::poll(std::time::Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        app.should_quit = true;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.next();
                        update_detail(&mut app);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.previous();
                        update_detail(&mut app);
                    }
                    KeyCode::Char('r') => match fetch_branches(&client).await {
                        Ok(branches) => {
                            app.branches = branches;
                            app.status_message =
                                format!("{} branches refreshed", app.branches.len());
                        }
                        Err(e) => {
                            app.status_message = format!("Refresh failed: {}", e);
                        }
                    },
                    KeyCode::Char('a') => {
                        if let Some(branch) = app.selected_branch() {
                            let id = branch.id.0.clone();
                            match client.approve_branch(&id).await {
                                Ok(result) => {
                                    // Q8: Prevent panic on short branch IDs
                                    app.status_message = format!(
                                        "Branch {} approved: {}",
                                        &id[..id.len().min(8)],
                                        result
                                    );
                                }
                                Err(e) => {
                                    app.status_message = format!("Approve failed: {}", e);
                                }
                            }
                        }
                    }
                    KeyCode::Char('x') => {
                        if let Some(branch) = app.selected_branch() {
                            let id = branch.id.0.clone();
                            // N6: Provide a meaningful reject reason instead of empty string
                            match client.reject_branch(&id, "rejected via TUI").await {
                                Ok(_) => {
                                    // Q8: Prevent panic on short branch IDs
                                    app.status_message =
                                        format!("Branch {} rejected", &id[..id.len().min(8)]);
                                }
                                Err(e) => {
                                    app.status_message = format!("Reject failed: {}", e);
                                }
                            }
                        }
                    }
                    KeyCode::Char('i') | KeyCode::Enter => {
                        if let Some(branch) = app.selected_branch() {
                            let id = branch.id.0.clone();
                            match client.inspect_branch(&id).await {
                                Ok(info) => {
                                    app.detail_text = format_json_pretty(&info);
                                }
                                Err(e) => {
                                    app.detail_text = format!("Inspect failed: {}", e);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
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

/// Draw the TUI layout.
fn draw_ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(f.area());

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[0]);

    // Branch list (left panel)
    let items: Vec<ListItem> = app
        .branches
        .iter()
        .map(|b| {
            let state_color = match b.state.as_str() {
                "active" | "Active" => Color::Green,
                "frozen" | "Frozen" => Color::Cyan,
                "committing" | "Committing" => Color::Yellow,
                "committed" | "Committed" => Color::Blue,
                "rolled_back" | "RolledBack" => Color::Red,
                "failed" | "Failed" => Color::Red,
                _ => Color::White,
            };

            let short_id = if b.id.0.len() > 8 {
                &b.id.0[..8]
            } else {
                &b.id.0
            };

            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", short_id), Style::default().fg(Color::White)),
                Span::styled(
                    format!("{:<12} ", b.state),
                    Style::default().fg(state_color),
                ),
                Span::styled(&b.profile, Style::default().fg(Color::Gray)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().title(" Branches ").borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(list, main_chunks[0], &mut app.list_state);

    // Detail panel (right)
    let detail = Paragraph::new(app.detail_text.as_str())
        .block(Block::default().title(" Details ").borders(Borders::ALL))
        .style(Style::default().fg(Color::White));

    f.render_widget(detail, main_chunks[1]);

    // Status bar
    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            " [a]pprove  [x]reject  [i]nspect  [r]efresh  [q]uit  ",
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(&app.status_message, Style::default().fg(Color::Cyan)),
    ]))
    .block(Block::default().borders(Borders::ALL));

    f.render_widget(status, chunks[1]);
}

/// Update the detail panel based on the selected branch.
fn update_detail(app: &mut App) {
    if let Some(branch) = app.selected_branch() {
        app.detail_text = format!(
            "Branch: {}\nProfile: {}\nState: {}\nPID: {}\nUID: {}",
            branch.id.0,
            branch.profile,
            branch.state,
            branch.pid.map(|p| p.to_string()).unwrap_or("none".into()),
            branch.uid,
        );
    } else {
        app.detail_text.clear();
    }
}

/// Fetch branches from puzzled via D-Bus.
async fn fetch_branches(client: &PuzzledClient) -> Result<Vec<BranchInfo>> {
    let json = client.list_branches().await?;
    let branches: Vec<BranchInfo> = serde_json::from_str(&json).context("parsing branch list")?;
    Ok(branches)
}

/// Pretty-format JSON string.
fn format_json_pretty(json: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| json.to_string()),
        Err(_) => json.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_new() {
        let app = App::new();
        assert!(app.branches.is_empty());
        assert!(!app.should_quit);
        assert!(app.detail_text.is_empty());
        assert!(!app.status_message.is_empty());
    }

    #[test]
    fn test_app_next_empty() {
        let mut app = App::new();
        app.next();
        assert_eq!(app.list_state.selected(), None);
    }

    #[test]
    fn test_app_previous_empty() {
        let mut app = App::new();
        app.previous();
        assert_eq!(app.list_state.selected(), None);
    }

    #[test]
    fn test_app_next_wraps() {
        let mut app = App::new();
        app.branches = vec![
            BranchInfo {
                id: BranchIdWrapper("aaa".to_string()),
                profile: "test".to_string(),
                state: "active".to_string(),
                pid: Some(123),
                uid: 1000,
            },
            BranchInfo {
                id: BranchIdWrapper("bbb".to_string()),
                profile: "test".to_string(),
                state: "frozen".to_string(),
                pid: None,
                uid: 1000,
            },
        ];
        app.list_state.select(Some(1));
        app.next();
        assert_eq!(app.list_state.selected(), Some(0));
    }

    #[test]
    fn test_app_previous_wraps() {
        let mut app = App::new();
        app.branches = vec![
            BranchInfo {
                id: BranchIdWrapper("aaa".to_string()),
                profile: "test".to_string(),
                state: "active".to_string(),
                pid: Some(123),
                uid: 1000,
            },
            BranchInfo {
                id: BranchIdWrapper("bbb".to_string()),
                profile: "test".to_string(),
                state: "frozen".to_string(),
                pid: None,
                uid: 1000,
            },
        ];
        app.list_state.select(Some(0));
        app.previous();
        assert_eq!(app.list_state.selected(), Some(1));
    }

    #[test]
    fn test_app_selected_branch() {
        let mut app = App::new();
        assert!(app.selected_branch().is_none());

        app.branches = vec![BranchInfo {
            id: BranchIdWrapper("test-id".to_string()),
            profile: "standard".to_string(),
            state: "active".to_string(),
            pid: Some(42),
            uid: 1000,
        }];
        app.list_state.select(Some(0));
        let branch = app.selected_branch().unwrap();
        assert_eq!(branch.id.0, "test-id");
        assert_eq!(branch.profile, "standard");
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
    fn test_update_detail() {
        let mut app = App::new();
        app.branches = vec![BranchInfo {
            id: BranchIdWrapper("branch-123".to_string()),
            profile: "restricted".to_string(),
            state: "frozen".to_string(),
            pid: Some(999),
            uid: 65534,
        }];
        app.list_state.select(Some(0));
        update_detail(&mut app);
        assert!(app.detail_text.contains("branch-123"));
        assert!(app.detail_text.contains("restricted"));
        assert!(app.detail_text.contains("frozen"));
        assert!(app.detail_text.contains("999"));
    }

    #[test]
    fn test_update_detail_no_selection() {
        let mut app = App::new();
        app.detail_text = "old text".to_string();
        update_detail(&mut app);
        assert!(app.detail_text.is_empty());
    }

    #[test]
    fn test_branch_info_deserialize() {
        let json = r#"{"id":"abc123","profile":"standard","state":"active","pid":42,"uid":1000}"#;
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
}
