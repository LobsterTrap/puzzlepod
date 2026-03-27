// SPDX-License-Identifier: Apache-2.0
//! Daemon status panel for the dashboard.

use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::tui::{app::App, theme::Theme};

pub fn draw_daemon_status(f: &mut Frame, app: &App, area: Rect, theme: &Theme, focused: bool) {
    let health_color = if app.daemon_status.connected {
        theme.status_ok
    } else {
        theme.status_err
    };
    let health_text = if app.daemon_status.connected {
        "Connected"
    } else {
        "Disconnected"
    };

    let line = Line::from(vec![
        Span::styled(" Bus: ", Style::default().fg(theme.text_dim)),
        Span::styled(
            &app.daemon_status.bus_type,
            Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  |  ", Style::default().fg(theme.border)),
        Span::styled("Branches: ", Style::default().fg(theme.text_dim)),
        Span::styled(
            app.daemon_status.branch_count.to_string(),
            Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  |  ", Style::default().fg(theme.border)),
        Span::styled("Health: ", Style::default().fg(theme.text_dim)),
        Span::styled(
            health_text,
            Style::default()
                .fg(health_color)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let block = Block::default()
        .title(" Daemon ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.block_style(focused));

    let paragraph = Paragraph::new(line).block(block);
    f.render_widget(paragraph, area);
}
