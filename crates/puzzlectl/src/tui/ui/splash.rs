//! Splash screen with ASCII art logo.

use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use crate::tui::{app::App, theme::Theme};

/// ASCII art for "PUZZLE" in block letters.
const PUZZLE_ART: &[&str] = &[
    " ____  _   _ _____ _____ _     _____",
    "|  _ \\| | | |__  /|__  /| |   | ____|",
    "| |_) | | | | / /   / / | |   |  _|",
    "|  __/| |_| |/ /__ / /_ | |___| |___",
    "|_|    \\___//_____|_____|_____|_____|",
];

/// ASCII art for "POD" in block letters.
const POD_ART: &[&str] = &[
    " ____   ___  ____",
    "|  _ \\ / _ \\|  _ \\",
    "| |_) | | | | | | |",
    "|  __/| |_| | |_| |",
    "|_|    \\___/|____/",
];

pub fn draw_splash(f: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    let chunks = Layout::default()
        .constraints([
            Constraint::Percentage(25),
            Constraint::Length(5),  // PUZZLE
            Constraint::Length(5),  // POD
            Constraint::Length(2),  // tagline
            Constraint::Length(2),  // version + badge
            Constraint::Length(2),  // prompt
            Constraint::Percentage(25),
        ])
        .split(area);

    // PUZZLE in accent purple
    let puzzle_lines: Vec<Line> = PUZZLE_ART
        .iter()
        .map(|line| Line::from(Span::styled(*line, Style::default().fg(theme.accent_bright).add_modifier(Modifier::BOLD))))
        .collect();
    let puzzle = Paragraph::new(puzzle_lines).alignment(Alignment::Center);
    f.render_widget(puzzle, chunks[1]);

    // POD in teal
    let pod_lines: Vec<Line> = POD_ART
        .iter()
        .map(|line| Line::from(Span::styled(*line, Style::default().fg(theme.status_ok).add_modifier(Modifier::BOLD))))
        .collect();
    let pod = Paragraph::new(pod_lines).alignment(Alignment::Center);
    f.render_widget(pod, chunks[2]);

    // Tagline
    let tagline = Paragraph::new(Line::from(vec![
        Span::styled(
            "Fork. Explore. Commit.",
            Style::default()
                .fg(theme.text_dim)
                .add_modifier(Modifier::ITALIC),
        ),
    ]))
    .alignment(Alignment::Center);
    f.render_widget(tagline, chunks[3]);

    // Version + ALPHA badge
    let version = env!("CARGO_PKG_VERSION");
    let elapsed = app.splash_start.elapsed().as_secs();
    let auto_hint = if elapsed >= 2 { " (advancing...)" } else { "" };
    let version_line = Paragraph::new(Line::from(vec![
        Span::styled(format!("v{} ", version), Style::default().fg(theme.muted)),
        Span::styled(
            " ALPHA ",
            Style::default()
                .fg(theme.bg_dark)
                .bg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(auto_hint, Style::default().fg(theme.text_dim)),
    ]))
    .alignment(Alignment::Center);
    f.render_widget(version_line, chunks[4]);

    // Prompt
    let prompt = Paragraph::new(Line::from(Span::styled(
        "press any key",
        Style::default().fg(theme.muted),
    )))
    .alignment(Alignment::Center);
    f.render_widget(prompt, chunks[5]);
}
