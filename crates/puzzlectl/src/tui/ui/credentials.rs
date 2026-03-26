//! Credential list table for the dashboard tab.

use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, Tabs},
    Frame,
};

use crate::tui::{
    app::{App, DashboardTab},
    theme::Theme,
};

pub fn draw_credential_list(f: &mut Frame, app: &mut App, area: Rect, theme: &Theme, focused: bool) {
    let chunks = ratatui::layout::Layout::default()
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .split(area);

    // Tab bar
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

    // Credential table
    if app.credentials.is_empty() {
        let empty = ratatui::widgets::Paragraph::new(
            " No credentials. Press [c] to create.",
        )
        .style(Style::default().fg(theme.muted))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border)),
        );
        f.render_widget(empty, chunks[1]);
        return;
    }

    let header = Row::new(vec![
        Cell::from(" NAME"),
        Cell::from("TYPE"),
        Cell::from("STATUS"),
    ])
    .style(
        Style::default()
            .fg(theme.accent_bright)
            .bg(theme.table_header_bg)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .credentials
        .iter()
        .map(|cred| {
            let name = cred
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let cred_type = cred
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let status = cred
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("active");

            let status_color = match status {
                "active" | "provisioned" => theme.status_ok,
                "expired" | "revoked" => theme.status_err,
                _ => theme.text_dim,
            };

            Row::new(vec![
                Cell::from(format!(" {}", name)).style(Style::default().fg(theme.text)),
                Cell::from(cred_type).style(Style::default().fg(theme.text_dim)),
                Cell::from(status).style(Style::default().fg(status_color)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border)),
    )
    .row_highlight_style(theme.highlight_style())
    .highlight_symbol("> ");

    // Note: credentials use ListState but we render as Table — use offset manually
    f.render_widget(table, chunks[1]);
}
