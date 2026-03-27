// SPDX-License-Identifier: Apache-2.0
//! UI screen router and shared chrome (title bar, nav bar, status bar).

pub mod audit_log;
pub mod branch_detail;
pub mod branch_draft;
pub mod branch_logs;
pub mod branch_policy;
pub mod branch_settings;
pub mod branches;
pub mod create_branch;
pub mod create_credential;
pub mod credentials;
pub mod daemon_settings;
pub mod daemon_status;
pub mod dashboard;
pub mod splash;

use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use super::app::{App, ConfirmDialog, Screen};
use super::theme::Theme;

/// Main draw function: routes to the active screen with chrome.
pub fn draw(f: &mut Frame, app: &mut App) {
    let theme = app.theme.clone();

    let chunks = Layout::default()
        .constraints([
            Constraint::Length(1), // title bar
            Constraint::Min(6),    // main content
            Constraint::Length(1), // nav bar
            Constraint::Length(1), // status bar
        ])
        .split(f.area());

    draw_title_bar(f, chunks[0], app, &theme);

    match &app.screen {
        Screen::Splash => {
            splash::draw_splash(f, app, chunks[1], &theme);
        }
        Screen::Dashboard => {
            dashboard::draw_dashboard(f, app, chunks[1], &theme);
        }
        Screen::BranchDetail(_) => {
            branch_detail::draw_branch_detail(f, app, chunks[1], &theme);
        }
        Screen::CreateBranch => {
            // Draw dashboard behind, then overlay form
            dashboard::draw_dashboard(f, app, chunks[1], &theme);
            create_branch::draw_create_branch(f, app, chunks[1], &theme);
        }
        Screen::CreateCredential => {
            dashboard::draw_dashboard(f, app, chunks[1], &theme);
            create_credential::draw_create_credential(f, app, chunks[1], &theme);
        }
        Screen::AuditLog => {
            audit_log::draw_audit_log(f, app, chunks[1], &theme);
        }
    }

    draw_nav_bar(f, chunks[2], app, &theme);
    draw_status_bar(f, chunks[3], app, &theme);

    // Confirm dialog overlay
    if let Some(ref dialog) = app.confirm_dialog {
        draw_confirm_dialog(f, f.area(), dialog, &theme);
    }

    // Notification toasts
    draw_notifications(f, f.area(), app, &theme);
}

fn draw_title_bar(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let health_indicator = if app.daemon_status.connected {
        Span::styled(" OK ", Style::default().fg(theme.status_ok))
    } else {
        Span::styled(" -- ", Style::default().fg(theme.status_err))
    };

    let mode_span = match app.dashboard_mode {
        super::app::DashboardMode::Live => Span::styled(
            " LIVE ",
            Style::default()
                .fg(theme.bg_dark)
                .bg(theme.status_ok)
                .add_modifier(Modifier::BOLD),
        ),
        super::app::DashboardMode::Log => Span::styled(
            " LOG ",
            Style::default()
                .fg(theme.bg_dark)
                .bg(theme.status_warn)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let line = Line::from(vec![
        Span::styled(
            " PUZZLEPOD ",
            Style::default()
                .fg(theme.bg_dark)
                .bg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        mode_span,
        Span::styled(
            format!("  {}  ", app.daemon_status.bus_type),
            Style::default().fg(theme.text_dim),
        ),
        health_indicator,
    ]);

    let paragraph = Paragraph::new(line).style(Style::default().bg(theme.table_header_bg));
    f.render_widget(paragraph, area);
}

fn draw_nav_bar(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let hints = keybinding_hints(app);
    let spans: Vec<Span> = hints
        .iter()
        .flat_map(|(key, desc)| {
            vec![
                Span::styled(
                    format!(" [{}]", key),
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{} ", desc), Style::default().fg(theme.text_dim)),
            ]
        })
        .collect();

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line).style(Style::default().bg(theme.table_header_bg));
    f.render_widget(paragraph, area);
}

fn draw_status_bar(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let style = if app.status_message.contains("failed")
        || app.status_message.contains("Failed")
        || app.status_message.contains("error")
    {
        Style::default().fg(theme.status_err)
    } else {
        Style::default().fg(theme.status_ok)
    };

    let paragraph = Paragraph::new(Span::styled(format!(" {}", app.status_message), style));
    f.render_widget(paragraph, area);
}

fn draw_confirm_dialog(f: &mut Frame, area: Rect, dialog: &ConfirmDialog, theme: &Theme) {
    let modal = centered_rect(50, 30, area);
    f.render_widget(Clear, modal);

    let block = Block::default()
        .title(format!(" {} ", dialog.title))
        .title_style(
            Style::default()
                .fg(theme.status_warn)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.status_warn));

    let inner = block.inner(modal);
    f.render_widget(block, modal);

    let chunks = Layout::default()
        .constraints([Constraint::Min(2), Constraint::Length(1)])
        .split(inner);

    let msg = Paragraph::new(dialog.message.as_str())
        .style(Style::default().fg(theme.text))
        .alignment(Alignment::Center);
    f.render_widget(msg, chunks[0]);

    let hint = Paragraph::new(Line::from(vec![
        Span::styled(
            " [y] ",
            Style::default()
                .fg(theme.status_ok)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("Confirm  ", Style::default().fg(theme.text_dim)),
        Span::styled(
            "[n/Esc] ",
            Style::default()
                .fg(theme.status_err)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("Cancel", Style::default().fg(theme.text_dim)),
    ]))
    .alignment(Alignment::Center);
    f.render_widget(hint, chunks[1]);
}

fn draw_notifications(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let active: Vec<_> = app
        .notifications
        .iter()
        .filter(|n| !n.is_expired())
        .collect();
    if active.is_empty() {
        return;
    }

    let max_show = 3;
    let count = active.len().min(max_show);
    let toast_height = count as u16;
    let toast_width = 50u16.min(area.width.saturating_sub(4));

    let x = area.width.saturating_sub(toast_width + 2);
    let y = area.height.saturating_sub(toast_height + 3);

    for (i, notif) in active.iter().take(max_show).enumerate() {
        let notif_area = Rect::new(x, y + i as u16, toast_width, 1);
        let color = theme.notification_color(&notif.level);
        let span = Span::styled(
            format!(" {} ", &notif.message),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        );
        f.render_widget(Paragraph::new(span), notif_area);
    }
}

fn keybinding_hints(app: &App) -> Vec<(&'static str, &'static str)> {
    if app.confirm_dialog.is_some() {
        return vec![("y", "confirm"), ("n", "cancel")];
    }

    match &app.screen {
        Screen::Splash => vec![("any", "continue")],
        Screen::Dashboard => vec![
            ("j/k", "navigate"),
            ("Tab", "focus"),
            ("Enter", "detail"),
            ("c", "create"),
            ("d", "delete"),
            ("h/l", "tab"),
            ("m", "mode"),
            ("L", "logs"),
            ("r", "refresh"),
            ("q", "quit"),
        ],
        Screen::BranchDetail(_) => {
            let mut hints = vec![("Esc", "back"), ("h/l", "tab"), ("j/k", "scroll")];
            // Check if branch is in GovernanceReview
            if let Some(b) = app.selected_branch() {
                if b.state == "GovernanceReview" || b.state == "governance_review" {
                    hints.push(("a", "approve"));
                    hints.push(("x", "reject"));
                }
            }
            hints.push(("i", "inspect"));
            hints.push(("r", "refresh"));
            hints.push(("y", "copy"));
            hints
        }
        Screen::AuditLog => vec![
            ("Esc", "back"),
            ("j/k", "scroll"),
            ("Tab", "filter"),
            ("Enter", "reload"),
            ("r", "refresh"),
        ],
        Screen::CreateBranch | Screen::CreateCredential => vec![
            ("Tab", "next"),
            ("S-Tab", "prev"),
            ("Enter", "submit"),
            ("Esc", "cancel"),
        ],
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
