//! Branch table for the dashboard.

use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
    Frame,
};

use crate::tui::{app::App, theme::Theme};

pub fn draw_branches_table(f: &mut Frame, app: &mut App, area: Rect, theme: &Theme, focused: bool) {
    let header = Row::new(vec![
        Cell::from(" ID"),
        Cell::from("STATE"),
        Cell::from("PROFILE"),
        Cell::from("TIME"),
        Cell::from("PID"),
    ])
    .style(
        Style::default()
            .fg(theme.accent_bright)
            .bg(theme.table_header_bg)
            .add_modifier(Modifier::BOLD),
    )
    .height(1);

    let rows: Vec<Row> = app
        .branches
        .iter()
        .map(|b| {
            let short_id = if b.id.0.len() > 12 {
                &b.id.0[..12]
            } else {
                &b.id.0
            };

            let state_color = theme.branch_state_color(&b.state);
            let pid_str = b.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
            let time_str = b.created_at.as_deref().map(|ts| {
                // Extract HH:MM:SS from ISO timestamp like "2026-03-26T19:14:18.123Z"
                if ts.len() >= 19 { &ts[11..19] } else { ts }
            }).unwrap_or("-");

            Row::new(vec![
                Cell::from(format!(" {}", short_id)).style(Style::default().fg(theme.text)),
                Cell::from(b.state.clone()).style(Style::default().fg(state_color)),
                Cell::from(b.profile.clone()).style(Style::default().fg(theme.text_dim)),
                Cell::from(time_str.to_string()).style(Style::default().fg(theme.muted)),
                Cell::from(pid_str).style(Style::default().fg(theme.muted)),
            ])
        })
        .collect();

    let empty_msg = if app.branches.is_empty() {
        " No branches. Press [c] to create."
    } else {
        ""
    };

    let block = Block::default()
        .title(" Branches ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.block_style(focused));

    let table = if app.branches.is_empty() {
        // Show empty state message
        let empty_row = Row::new(vec![Cell::from(empty_msg)
            .style(Style::default().fg(theme.muted))]);
        Table::new(vec![empty_row], [Constraint::Percentage(100)])
            .block(block)
            .row_highlight_style(theme.highlight_style())
            .highlight_symbol("> ")
    } else {
        Table::new(
            rows,
            [
                Constraint::Percentage(25),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(15),
            ],
        )
        .header(header)
        .block(block)
        .row_highlight_style(theme.highlight_style())
        .highlight_symbol("> ")
    };

    f.render_stateful_widget(table, area, &mut app.branch_table_state);
}
