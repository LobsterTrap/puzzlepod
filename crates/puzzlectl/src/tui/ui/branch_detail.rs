//! Branch detail view: metadata sidebar + tabbed content.

use ratatui::{
    layout::{Constraint, Layout, Direction, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
    Frame,
};

use crate::tui::{
    app::{App, BranchDetailTab, DetailFocus, Screen},
    theme::Theme,
};

use super::{branch_draft, branch_logs, branch_policy, branch_settings};

pub fn draw_branch_detail(f: &mut Frame, app: &mut App, area: Rect, theme: &Theme) {
    let branch_id = match &app.screen {
        Screen::BranchDetail(id) => id.clone(),
        _ => return,
    };

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(22), Constraint::Percentage(78)])
        .split(area);

    // -- Metadata sidebar --
    draw_metadata_sidebar(f, app, &branch_id, chunks[0], theme);

    // -- Tabbed content area --
    let content_chunks = Layout::default()
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .split(chunks[1]);

    // Tab bar
    let tab_titles = vec!["Logs", "Diff/Draft", "Policy", "Settings"];
    let selected_idx = match app.detail_tab {
        BranchDetailTab::Logs => 0,
        BranchDetailTab::DiffDraft => 1,
        BranchDetailTab::Policy => 2,
        BranchDetailTab::Settings => 3,
    };

    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme.block_style(app.detail_focus == DetailFocus::Content))
                .title(" Detail ")
                .title_style(theme.title_style()),
        )
        .select(selected_idx)
        .style(Style::default().fg(theme.text_dim))
        .highlight_style(
            Style::default()
                .fg(theme.accent_bright)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, content_chunks[0]);

    // Tab content
    match app.detail_tab {
        BranchDetailTab::Logs => {
            branch_logs::draw_logs(f, app, content_chunks[1], theme);
        }
        BranchDetailTab::DiffDraft => {
            branch_draft::draw_governance_review(f, app, content_chunks[1], theme);
        }
        BranchDetailTab::Policy => {
            branch_policy::draw_policy(f, app, content_chunks[1], theme);
        }
        BranchDetailTab::Settings => {
            branch_settings::draw_settings(f, app, content_chunks[1], theme);
        }
    }
}

fn draw_metadata_sidebar(f: &mut Frame, app: &App, branch_id: &str, area: Rect, theme: &Theme) {
    let branch = app.branches.iter().find(|b| b.id.0 == branch_id);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("ID: ", Style::default().fg(theme.text_dim)),
            Span::styled(branch_id, Style::default().fg(theme.text).add_modifier(Modifier::BOLD)),
        ]),
    ];

    if let Some(b) = branch {
        let state_color = theme.branch_state_color(&b.state);
        lines.push(Line::from(vec![
            Span::styled("State: ", Style::default().fg(theme.text_dim)),
            Span::styled(&b.state, Style::default().fg(state_color).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Profile: ", Style::default().fg(theme.text_dim)),
            Span::styled(&b.profile, Style::default().fg(theme.text)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("PID: ", Style::default().fg(theme.text_dim)),
            Span::styled(
                b.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                Style::default().fg(theme.text),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("UID: ", Style::default().fg(theme.text_dim)),
            Span::styled(b.uid.to_string(), Style::default().fg(theme.text)),
        ]));
        if let Some(ref created) = b.created_at {
            lines.push(Line::from(vec![
                Span::styled("Created: ", Style::default().fg(theme.text_dim)),
                Span::styled(created, Style::default().fg(theme.muted)),
            ]));
        }
        if let Some(ref expires) = b.expires_at {
            lines.push(Line::from(vec![
                Span::styled("Expires: ", Style::default().fg(theme.text_dim)),
                Span::styled(expires, Style::default().fg(theme.muted)),
            ]));
        }
        if let Some(ref ctx) = b.selinux_context {
            lines.push(Line::from(vec![
                Span::styled("SELinux: ", Style::default().fg(theme.text_dim)),
                Span::styled(ctx, Style::default().fg(theme.muted)),
            ]));
        }
    }

    // Show inspect data if available
    if let Some(ref info) = app.detail_info {
        lines.push(Line::from(""));
        if let Some(obj) = info.as_object() {
            for (key, val) in obj {
                // Skip fields already shown above
                if matches!(key.as_str(), "id" | "profile" | "state" | "pid" | "uid" | "created_at" | "expires_at" | "selinux_context" | "base_path" | "upper_dir" | "work_dir") {
                    continue;
                }
                let val_str = match val {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                if !val_str.is_empty() && val_str != "null" {
                    lines.push(Line::from(vec![
                        Span::styled(format!("{}: ", key), Style::default().fg(theme.text_dim)),
                        Span::styled(val_str, Style::default().fg(theme.muted)),
                    ]));
                }
            }
        }
    }

    let block = Block::default()
        .title(" Info ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.block_style(app.detail_focus == DetailFocus::Metadata));

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}
