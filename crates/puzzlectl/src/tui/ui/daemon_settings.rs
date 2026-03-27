// SPDX-License-Identifier: Apache-2.0
//! Daemon configuration read-only display.

use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
    Frame,
};

use crate::tui::{
    app::{App, DashboardTab},
    theme::Theme,
};

pub fn draw_daemon_settings(f: &mut Frame, app: &App, area: Rect, theme: &Theme, focused: bool) {
    let chunks = ratatui::layout::Layout::default()
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .split(area);

    // Tab bar (shared with credentials)
    let tab_titles = vec!["Credentials", "Settings"];
    let selected = match app.dashboard_tab {
        DashboardTab::Credentials => 0,
        DashboardTab::Settings => 1,
    };
    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme.block_style(focused)),
        )
        .select(selected)
        .style(Style::default().fg(theme.text_dim))
        .highlight_style(
            Style::default()
                .fg(theme.accent_bright)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, chunks[0]);

    // Settings display
    let lines = vec![
        Line::from(vec![
            Span::styled(" Bus Type: ", Style::default().fg(theme.text_dim)),
            Span::styled(&app.daemon_status.bus_type, Style::default().fg(theme.text)),
        ]),
        Line::from(vec![
            Span::styled(" Connected: ", Style::default().fg(theme.text_dim)),
            Span::styled(
                if app.daemon_status.connected {
                    "Yes"
                } else {
                    "No"
                },
                Style::default().fg(if app.daemon_status.connected {
                    theme.status_ok
                } else {
                    theme.status_err
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Active Branches: ", Style::default().fg(theme.text_dim)),
            Span::styled(
                app.daemon_status.branch_count.to_string(),
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Policy Loaded: ", Style::default().fg(theme.text_dim)),
            Span::styled(
                if app.daemon_status.policy_loaded {
                    "Yes"
                } else {
                    "No"
                },
                Style::default().fg(if app.daemon_status.policy_loaded {
                    theme.status_ok
                } else {
                    theme.status_warn
                }),
            ),
        ]),
    ];

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border)),
    );
    f.render_widget(paragraph, chunks[1]);
}
