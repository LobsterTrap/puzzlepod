//! Dashboard layout: daemon status + tab content + branches table.

use ratatui::{
    layout::{Constraint, Layout, Rect},
    Frame,
};

use crate::tui::{
    app::{App, DashboardFocus, DashboardTab},
    theme::Theme,
};

use super::{branches, credentials, daemon_settings, daemon_status};

pub fn draw_dashboard(f: &mut Frame, app: &mut App, area: Rect, theme: &Theme) {
    let chunks = Layout::default()
        .constraints([
            Constraint::Length(3),     // Daemon status
            Constraint::Percentage(30), // Tab content
            Constraint::Min(8),        // Branches table
        ])
        .split(area);

    // Daemon status panel
    daemon_status::draw_daemon_status(
        f,
        app,
        chunks[0],
        theme,
        app.dashboard_focus == DashboardFocus::DaemonStatus,
    );

    // Tab content (credentials or daemon settings)
    let tab_focused = app.dashboard_focus == DashboardFocus::TabContent;
    match app.dashboard_tab {
        DashboardTab::Credentials => {
            credentials::draw_credential_list(f, app, chunks[1], theme, tab_focused);
        }
        DashboardTab::Settings => {
            daemon_settings::draw_daemon_settings(f, app, chunks[1], theme, tab_focused);
        }
    }

    // Branches table
    branches::draw_branches_table(
        f,
        app,
        chunks[2],
        theme,
        app.dashboard_focus == DashboardFocus::BranchTable,
    );
}
