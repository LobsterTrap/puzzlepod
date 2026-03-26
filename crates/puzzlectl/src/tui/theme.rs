//! Cyberpunk purple/magenta theme system for PuzzlePod TUI.
//!
//! Supports auto-detection of terminal dark/light mode via terminal-colorsaurus,
//! with a dark theme fallback.

use ratatui::style::{Color, Modifier, Style};

/// Terminal color scheme detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeMode {
    Dark,
    Light,
}

/// Cyberpunk purple/magenta color palette.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Theme {
    pub accent: Color,
    pub accent_bright: Color,
    pub bg_dark: Color,
    pub border: Color,
    pub border_focused: Color,
    pub text: Color,
    pub text_dim: Color,
    pub muted: Color,
    pub highlight_bg: Color,
    pub table_header_bg: Color,
    pub status_ok: Color,
    pub status_warn: Color,
    pub status_err: Color,
    pub mode: ThemeMode,
}

#[allow(dead_code)]
impl Theme {
    /// Dark cyberpunk theme (default).
    pub fn dark() -> Self {
        Self {
            accent: Color::Rgb(187, 134, 252),        // #BB86FC
            accent_bright: Color::Rgb(207, 110, 255),  // #CF6EFF
            bg_dark: Color::Rgb(26, 0, 51),            // #1A0033
            border: Color::Rgb(61, 31, 110),           // #3D1F6E
            border_focused: Color::Rgb(187, 134, 252), // #BB86FC
            text: Color::Rgb(232, 222, 248),           // #E8DEF8
            text_dim: Color::Rgb(149, 117, 205),       // #9575CD
            muted: Color::Rgb(149, 117, 205),          // #9575CD
            highlight_bg: Color::Rgb(61, 31, 110),     // #3D1F6E
            table_header_bg: Color::Rgb(42, 16, 82),   // #2A1052
            status_ok: Color::Rgb(3, 218, 198),        // #03DAC6
            status_warn: Color::Rgb(255, 183, 77),     // #FFB74D
            status_err: Color::Rgb(207, 102, 121),     // #CF6679
            mode: ThemeMode::Dark,
        }
    }

    /// Light cyberpunk theme (inverted backgrounds).
    pub fn light() -> Self {
        Self {
            accent: Color::Rgb(128, 60, 200),          // darker purple for contrast
            accent_bright: Color::Rgb(156, 39, 220),   // #9C27DC
            bg_dark: Color::Rgb(245, 240, 255),        // light lavender bg
            border: Color::Rgb(180, 160, 210),         // light purple border
            border_focused: Color::Rgb(128, 60, 200),  // darker purple
            text: Color::Rgb(30, 10, 50),              // near-black purple
            text_dim: Color::Rgb(100, 80, 140),        // medium purple
            muted: Color::Rgb(140, 120, 170),          // muted purple
            highlight_bg: Color::Rgb(220, 200, 245),   // soft lavender
            table_header_bg: Color::Rgb(230, 215, 250), // pale lavender
            status_ok: Color::Rgb(0, 150, 136),        // darker teal
            status_warn: Color::Rgb(230, 140, 0),      // darker amber
            status_err: Color::Rgb(180, 60, 80),       // darker rose
            mode: ThemeMode::Light,
        }
    }

    /// Auto-detect terminal background and choose theme.
    pub fn detect() -> Self {
        match terminal_colorsaurus::color_scheme(terminal_colorsaurus::QueryOptions::default()) {
            Ok(scheme) => match scheme {
                terminal_colorsaurus::ColorScheme::Dark => Self::dark(),
                terminal_colorsaurus::ColorScheme::Light => Self::light(),
            },
            Err(_) => Self::dark(), // fallback
        }
    }

    /// Style for block borders (focused vs unfocused).
    pub fn block_style(&self, focused: bool) -> Style {
        if focused {
            Style::default().fg(self.border_focused)
        } else {
            Style::default().fg(self.border)
        }
    }

    /// Title bar style.
    pub fn title_style(&self) -> Style {
        Style::default()
            .fg(self.accent_bright)
            .add_modifier(Modifier::BOLD)
    }

    /// Row highlight style (selected item).
    pub fn highlight_style(&self) -> Style {
        Style::default()
            .fg(self.text)
            .bg(self.highlight_bg)
            .add_modifier(Modifier::BOLD)
    }

    /// Keybinding hint style.
    pub fn keybinding_style(&self) -> Style {
        Style::default().fg(self.accent)
    }

    /// Status bar message style.
    pub fn status_style(&self) -> Style {
        Style::default().fg(self.status_ok)
    }

    /// Color for a branch state string.
    pub fn branch_state_color(&self, state: &str) -> Color {
        match state {
            "active" | "Active" => self.status_ok,
            "governance_review" | "GovernanceReview" => self.status_warn,
            "frozen" | "Frozen" => self.accent,
            "committing" | "Committing" => self.text_dim,
            "committed" | "Committed" => self.muted,
            "rolled_back" | "RolledBack" => self.status_err,
            "failed" | "Failed" => self.status_err,
            "terminated" | "Terminated" => self.status_err,
            "degraded" | "Degraded" => self.status_warn,
            "creating" | "Creating" => self.text_dim,
            "ready" | "Ready" => self.text_dim,
            "exited" | "Exited" => self.muted,
            _ => self.text,
        }
    }

    /// Color for a file change kind.
    pub fn change_kind_color(&self, kind: &str) -> Color {
        match kind {
            "Added" | "Created" => self.status_ok,
            "Modified" => self.status_warn,
            "Deleted" => self.status_err,
            "MetadataChanged" | "PermissionChanged" => Color::Rgb(3, 218, 198), // teal
            "Renamed" => self.accent,
            _ => self.text,
        }
    }

    /// Color for violation severity.
    pub fn severity_color(&self, severity: &str) -> Color {
        match severity {
            "Warning" => self.status_warn,
            "Error" => self.status_err,
            "Critical" => Color::Rgb(255, 50, 50), // bright red
            _ => self.text,
        }
    }

    /// Color for notification level.
    pub fn notification_color(&self, level: &NotificationLevel) -> Color {
        match level {
            NotificationLevel::Info => self.accent,
            NotificationLevel::Warning => self.status_warn,
            NotificationLevel::Error => self.status_err,
        }
    }
}

/// Notification severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationLevel {
    Info,
    Warning,
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dark_theme_colors() {
        let theme = Theme::dark();
        assert_eq!(theme.mode, ThemeMode::Dark);
        assert_eq!(theme.accent, Color::Rgb(187, 134, 252));
        assert_eq!(theme.status_ok, Color::Rgb(3, 218, 198));
    }

    #[test]
    fn test_light_theme_colors() {
        let theme = Theme::light();
        assert_eq!(theme.mode, ThemeMode::Light);
    }

    #[test]
    fn test_branch_state_colors_all_variants() {
        let theme = Theme::dark();
        let states = [
            "active", "Active", "frozen", "Frozen", "committing", "Committing",
            "committed", "Committed", "rolled_back", "RolledBack", "failed", "Failed",
            "governance_review", "GovernanceReview", "terminated", "Terminated",
            "degraded", "Degraded", "creating", "Creating", "ready", "Ready",
            "exited", "Exited", "unknown",
        ];
        for state in states {
            let _ = theme.branch_state_color(state);
        }
    }

    #[test]
    fn test_highlight_style() {
        let theme = Theme::dark();
        let style = theme.highlight_style();
        assert!(style.add_modifier.contains(Modifier::BOLD));
    }
}
