// SPDX-License-Identifier: Apache-2.0
//! Policy evaluation result display.

use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::tui::{app::App, theme::Theme};

pub fn draw_policy(f: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    if app.policy_text.is_empty() {
        let empty = Paragraph::new(" No policy data. Press [i] to inspect branch.")
            .style(Style::default().fg(theme.muted))
            .block(
                Block::default()
                    .title(" Policy ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(theme.border)),
            );
        f.render_widget(empty, area);
        return;
    }

    // Build lines with owned strings to avoid lifetime issues
    let lines = format_policy_text(&app.policy_text, theme);

    let block = Block::default()
        .title(" Policy Evaluation ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));

    let paragraph = Paragraph::new(lines)
        .block(block)
        .scroll((app.detail_scroll, 0));
    f.render_widget(paragraph, area);
}

fn format_policy_text<'a>(text: &str, theme: &Theme) -> Vec<Line<'a>> {
    let val: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            return text
                .lines()
                .map(|l| Line::from(Span::styled(l.to_string(), Style::default().fg(theme.text))))
                .collect();
        }
    };

    let mut lines = Vec::new();

    // Policy decision
    if let Some(decision) = val.get("policy_result").and_then(|v| v.as_str()) {
        let (badge, color) = match decision {
            "Approved" => (" APPROVED ", theme.status_ok),
            _ if decision.starts_with("Rejected") => (" REJECTED ", theme.status_err),
            _ => (" REVIEW ", theme.status_warn),
        };
        lines.push(Line::from(vec![
            Span::styled(
                "Decision: ".to_string(),
                Style::default().fg(theme.text_dim),
            ),
            Span::styled(
                badge.to_string(),
                Style::default()
                    .fg(theme.bg_dark)
                    .bg(color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(""));
    }

    // Violations
    if let Some(violations) = val.get("violations").and_then(|v| v.as_array()) {
        if !violations.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("Violations ({}):", violations.len()),
                Style::default()
                    .fg(theme.status_err)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));

            for v in violations {
                let rule = v.get("rule").and_then(|r| r.as_str()).unwrap_or("unknown");
                let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("");
                let severity = v
                    .get("severity")
                    .and_then(|s| s.as_str())
                    .unwrap_or("Error");
                let sev_color = theme.severity_color(severity);

                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  [{}] ", severity),
                        Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(rule.to_string(), Style::default().fg(theme.accent)),
                ]));
                lines.push(Line::from(Span::styled(
                    format!("    {}", msg),
                    Style::default().fg(theme.text),
                )));
                lines.push(Line::from(""));
            }
        }
    }

    // File stats
    if let Some(files) = val.get("files_committed").and_then(|v| v.as_u64()) {
        let bytes = val
            .get("bytes_committed")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        lines.push(Line::from(vec![
            Span::styled("Files: ".to_string(), Style::default().fg(theme.text_dim)),
            Span::styled(files.to_string(), Style::default().fg(theme.text)),
            Span::styled("  Bytes: ".to_string(), Style::default().fg(theme.text_dim)),
            Span::styled(bytes.to_string(), Style::default().fg(theme.text)),
        ]));
    }

    if lines.is_empty() {
        let pretty = serde_json::to_string_pretty(&val).unwrap_or_default();
        for line in pretty.lines() {
            lines.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(theme.text),
            )));
        }
    }

    lines
}
