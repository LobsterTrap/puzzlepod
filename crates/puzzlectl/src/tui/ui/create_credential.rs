// SPDX-License-Identifier: Apache-2.0
//! Create credential modal form.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use crate::tui::{app::App, theme::Theme};

pub fn draw_create_credential(f: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    let modal_area = centered_rect(60, 55, area);

    f.render_widget(Clear, modal_area);

    let block = Block::default()
        .title(" Create Credential ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.accent_bright));

    let inner = block.inner(modal_area);
    f.render_widget(block, modal_area);

    let field_count = app.create_credential_fields.len();
    let mut constraints: Vec<Constraint> = Vec::new();
    for _ in 0..field_count {
        constraints.push(Constraint::Length(3));
    }
    constraints.push(Constraint::Length(2));
    constraints.push(Constraint::Min(0));

    let chunks = Layout::default().constraints(constraints).split(inner);

    for (i, field) in app.create_credential_fields.iter().enumerate() {
        let focused = i == app.create_credential_focus;
        let border_color = if focused {
            theme.accent_bright
        } else {
            theme.border
        };

        let display_value = if let Some(ref opts) = field.options {
            opts.get(field.selected_option).cloned().unwrap_or_default()
        } else {
            let cursor = if focused { "_" } else { "" };
            format!("{}{}", field.value, cursor)
        };

        let field_widget = Paragraph::new(Line::from(vec![Span::styled(
            &display_value,
            Style::default().fg(theme.text),
        )]))
        .block(
            Block::default()
                .title(format!(" {} ", field.label))
                .title_style(if focused {
                    Style::default()
                        .fg(theme.accent_bright)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.text_dim)
                })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        );

        f.render_widget(field_widget, chunks[i]);
    }

    let hint = Paragraph::new(Line::from(vec![
        Span::styled(
            " [Enter] ",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("Submit  ", Style::default().fg(theme.text_dim)),
        Span::styled(
            "[Esc] ",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("Cancel  ", Style::default().fg(theme.text_dim)),
        Span::styled(
            "[Tab] ",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("Next field", Style::default().fg(theme.text_dim)),
    ]))
    .alignment(Alignment::Center);
    f.render_widget(hint, chunks[field_count]);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
