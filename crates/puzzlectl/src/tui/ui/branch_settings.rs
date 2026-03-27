// SPDX-License-Identifier: Apache-2.0
//! Branch profile/settings read-only display.

use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::tui::{app::App, theme::Theme};

pub fn draw_settings(f: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    let branch = match &app.screen {
        crate::tui::app::Screen::BranchDetail(id) => app.branches.iter().find(|b| b.id.0 == *id),
        _ => None,
    };

    let mut lines = Vec::new();

    if let Some(b) = branch {
        lines.push(Line::from(vec![
            Span::styled("Profile: ", Style::default().fg(theme.text_dim)),
            Span::styled(&b.profile, Style::default().fg(theme.accent)),
        ]));
        lines.push(Line::from(""));
    }

    // Show detailed inspect info if available
    if let Some(ref info) = app.detail_info {
        if let Some(obj) = info.as_object() {
            for (key, val) in obj {
                let val_str = match val {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Null => continue,
                    other => {
                        serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string())
                    }
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("{}: ", key), Style::default().fg(theme.text_dim)),
                    Span::styled(val_str, Style::default().fg(theme.text)),
                ]));
            }
        }
    } else {
        lines.push(Line::from(Span::styled(
            " Press [i] to load branch details.",
            Style::default().fg(theme.muted),
        )));
    }

    let block = Block::default()
        .title(" Branch Settings ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));

    let paragraph = Paragraph::new(lines)
        .block(block)
        .scroll((app.detail_scroll, 0));
    f.render_widget(paragraph, area);
}
