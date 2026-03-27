// SPDX-License-Identifier: Apache-2.0
//! Full-screen audit log viewer (log mode).

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
    },
    Frame,
};

use crate::tui::{app::App, theme::Theme};

pub fn draw_audit_log(f: &mut Frame, app: &mut App, area: Rect, theme: &Theme) {
    let chunks = Layout::default()
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .split(area);

    // Filter bar with editable fields
    let branch_style = if app.audit_log_filter_focus == 0 {
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.text_dim)
    };
    let type_style = if app.audit_log_filter_focus == 1 {
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.text_dim)
    };

    let branch_val = if app.audit_log_filter_branch.is_empty() {
        "*".to_string()
    } else {
        app.audit_log_filter_branch.clone()
    };
    let type_val = if app.audit_log_filter_type.is_empty() {
        "*".to_string()
    } else {
        app.audit_log_filter_type.clone()
    };

    let filter_line = Line::from(vec![
        Span::styled(" Branch: ", Style::default().fg(theme.text)),
        Span::styled(format!("{:<16}", branch_val), branch_style),
        Span::styled("  Type: ", Style::default().fg(theme.text)),
        Span::styled(format!("{:<20}", type_val), type_style),
        Span::styled(
            format!("  {} events", app.audit_log_events.len()),
            Style::default().fg(theme.muted),
        ),
    ]);

    let filter = Paragraph::new(filter_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border))
            .title(" Audit Log ")
            .title_style(theme.title_style()),
    );
    f.render_widget(filter, chunks[0]);

    // Event list
    if app.audit_log_events.is_empty() {
        let empty = Paragraph::new(" No audit events. Press [Enter] to reload or adjust filters.")
            .style(Style::default().fg(theme.muted))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(theme.border)),
            );
        f.render_widget(empty, chunks[1]);
        return;
    }

    let total = app.audit_log_events.len();
    // Clamp scroll
    let max_scroll = total.saturating_sub(1);
    if (app.audit_log_scroll as usize) > max_scroll {
        app.audit_log_scroll = max_scroll as u16;
    }

    let visible_height = chunks[1].height.saturating_sub(2) as usize;
    let offset = app.audit_log_scroll as usize;
    let visible_items: Vec<ListItem> = app
        .audit_log_events
        .iter()
        .skip(offset)
        .take(visible_height)
        .map(|evt| format_audit_event(evt, theme))
        .collect();

    let visible_list = List::new(visible_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border)),
    );
    f.render_widget(visible_list, chunks[1]);

    // Scrollbar
    if total > visible_height {
        let mut scrollbar_state =
            ScrollbarState::new(total).position(app.audit_log_scroll as usize);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .style(Style::default().fg(theme.accent));
        f.render_stateful_widget(scrollbar, chunks[1], &mut scrollbar_state);
    }
}

fn format_audit_event<'a>(evt: &serde_json::Value, theme: &Theme) -> ListItem<'a> {
    // Handle both flat and nested event schemas
    let (event_type, timestamp, branch_id, details) = if let Some(event_obj) = evt.get("event") {
        // Nested: { seq, timestamp, event: { event_type, branch_id, details } }
        let event_type = event_obj
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let timestamp = evt.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let branch_id = event_obj
            .get("branch_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let details = event_obj.get("details").cloned().unwrap_or_default();
        (
            event_type.to_string(),
            timestamp.to_string(),
            branch_id.to_string(),
            details,
        )
    } else {
        // Flat: { event_type, timestamp, branch_id, details }
        let event_type = evt
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let timestamp = evt.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let branch_id = evt.get("branch_id").and_then(|v| v.as_str()).unwrap_or("");
        let details = evt.get("details").cloned().unwrap_or_default();
        (
            event_type.to_string(),
            timestamp.to_string(),
            branch_id.to_string(),
            details,
        )
    };

    let type_color = match event_type.as_str() {
        "policy_violation" | "dlp_violation" | "commit_rejected" => theme.status_err,
        "branch_committed" | "branch_created" => theme.status_ok,
        "governance_review_pending" | "behavioral_trigger" | "branch_rolled_back" => {
            theme.status_warn
        }
        _ => theme.text_dim,
    };

    let short_ts = if timestamp.len() > 19 {
        &timestamp[11..19] // extract HH:MM:SS from ISO timestamp
    } else if timestamp.len() > 8 {
        &timestamp[..8]
    } else {
        &timestamp
    };
    let short_branch = if branch_id.len() > 8 {
        &branch_id[..8]
    } else {
        &branch_id
    };

    // Summarize details
    let detail_summary = summarize_details(&event_type, &details);

    ListItem::new(Line::from(vec![
        Span::styled(format!("{} ", short_ts), Style::default().fg(theme.muted)),
        Span::styled(
            format!("{:<22} ", event_type),
            Style::default().fg(type_color),
        ),
        Span::styled(
            format!("{:<10} ", short_branch),
            Style::default().fg(theme.text_dim),
        ),
        Span::styled(detail_summary, Style::default().fg(theme.text)),
    ]))
}

fn summarize_details(event_type: &str, details: &serde_json::Value) -> String {
    match event_type {
        "branch_created" => {
            let profile = details
                .get("profile")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let uid = details.get("uid").and_then(|v| v.as_u64()).unwrap_or(0);
            format!("profile={} uid={}", profile, uid)
        }
        "branch_committed" => {
            let files = details.get("files").and_then(|v| v.as_u64()).unwrap_or(0);
            let bytes = details.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            format!("{} files, {} bytes", files, bytes)
        }
        "branch_rolled_back" => details
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "policy_violation" => {
            let rule = details.get("rule").and_then(|v| v.as_str()).unwrap_or("");
            let msg = details
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !msg.is_empty() {
                format!("{}: {}", rule, msg)
            } else {
                rule.to_string()
            }
        }
        "commit_rejected" => details
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "profile_loaded" => details
            .get("profile")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => {
            // Generic: show first key=value pair
            if let Some(obj) = details.as_object() {
                obj.iter()
                    .take(2)
                    .map(|(k, v)| {
                        let val = match v {
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        format!("{}={}", k, val)
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                String::new()
            }
        }
    }
}
