// SPDX-License-Identifier: Apache-2.0
//! Audit event log viewer.

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
    },
    Frame,
};

use crate::tui::{app::App, theme::Theme};

pub fn draw_logs(f: &mut Frame, app: &mut App, area: Rect, theme: &Theme) {
    let chunks = Layout::default()
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .split(area);

    // Filter bar
    let filter_text = format!(
        " Filter: {} ",
        if app.audit_events.is_empty() {
            "(no events)"
        } else {
            ""
        }
    );
    let filter = Paragraph::new(filter_text)
        .style(Style::default().fg(theme.text_dim))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(" Audit Log ")
                .title_style(theme.title_style()),
        );
    f.render_widget(filter, chunks[0]);

    // Log entries
    if app.audit_events.is_empty() {
        let empty = Paragraph::new(" No audit events. Press [r] to refresh.")
            .style(Style::default().fg(theme.muted))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(theme.border)),
            );
        f.render_widget(empty, chunks[1]);
        return;
    }

    let items: Vec<ListItem> = app
        .audit_events
        .iter()
        .map(|evt| {
            let event_type = evt
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let timestamp = evt.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let branch_id = evt.get("branch_id").and_then(|v| v.as_str()).unwrap_or("");
            let details = evt.get("details").and_then(|v| v.as_str()).unwrap_or("");

            let type_color = match event_type {
                "policy_violation" | "dlp_violation" => theme.status_err,
                "branch_committed" | "branch_created" => theme.status_ok,
                "governance_review_pending" | "behavioral_trigger" => theme.status_warn,
                _ => theme.text_dim,
            };

            let short_ts = if timestamp.len() > 19 {
                &timestamp[..19]
            } else {
                timestamp
            };
            let short_branch = if branch_id.len() > 8 {
                &branch_id[..8]
            } else {
                branch_id
            };

            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", short_ts), Style::default().fg(theme.muted)),
                Span::styled(
                    format!("{:<20} ", event_type),
                    Style::default().fg(type_color),
                ),
                Span::styled(
                    format!("{} ", short_branch),
                    Style::default().fg(theme.text_dim),
                ),
                Span::styled(details, Style::default().fg(theme.text)),
            ]))
        })
        .collect();

    let total = items.len();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border)),
        )
        .highlight_style(theme.highlight_style())
        .highlight_symbol("> ");
    f.render_widget(list, chunks[1]);

    // Scrollbar
    if total > 0 {
        let mut scrollbar_state = ScrollbarState::new(total).position(app.audit_scroll as usize);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .style(Style::default().fg(theme.accent));
        f.render_stateful_widget(scrollbar, chunks[1], &mut scrollbar_state);
    }
}
