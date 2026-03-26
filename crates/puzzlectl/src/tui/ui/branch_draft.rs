//! Governance review: diff display with approve/reject actions.

use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::tui::{app::App, theme::Theme};

pub fn draw_governance_review(f: &mut Frame, app: &mut App, area: Rect, theme: &Theme) {
    if app.detail_diff.is_empty() {
        let msg = " No diff data. Press [r] to refresh or [i] to inspect.";
        let empty = Paragraph::new(msg)
            .style(Style::default().fg(theme.muted))
            .block(
                Block::default()
                    .title(" Governance Review ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(theme.border)),
            );
        f.render_widget(empty, area);
        return;
    }

    let items: Vec<ListItem> = app
        .detail_diff
        .iter()
        .map(|change| {
            let kind = change
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let path = change
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let size = change
                .get("size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let old_size = change
                .get("old_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let kind_color = theme.change_kind_color(kind);

            let size_delta = if size > old_size {
                format!("+{}", size - old_size)
            } else if old_size > size {
                format!("-{}", old_size - size)
            } else {
                "0".to_string()
            };

            // Permission changes
            let mode_info = match (
                change.get("old_mode").and_then(|v| v.as_u64()),
                change.get("new_mode").and_then(|v| v.as_u64()),
            ) {
                (Some(old), Some(new)) if old != new => {
                    format!(" {:o}->{:o}", old, new)
                }
                _ => String::new(),
            };

            let kind_symbol = match kind {
                "Added" | "Created" => "+",
                "Deleted" => "-",
                "Modified" => "~",
                "MetadataChanged" | "PermissionChanged" => "M",
                "Renamed" => "R",
                _ => "?",
            };

            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {} ", kind_symbol),
                    Style::default()
                        .fg(kind_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<12} ", kind),
                    Style::default().fg(kind_color),
                ),
                Span::styled(path, Style::default().fg(theme.text)),
                Span::styled(
                    format!("  ({} bytes{})", size_delta, mode_info),
                    Style::default().fg(theme.text_dim),
                ),
            ]))
        })
        .collect();

    let block = Block::default()
        .title(" Governance Review — File Changes ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));

    let list = List::new(items)
        .block(block)
        .highlight_style(theme.highlight_style())
        .highlight_symbol("> ");
    f.render_widget(list, area);
}
