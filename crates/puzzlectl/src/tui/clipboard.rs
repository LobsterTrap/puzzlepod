//! OSC 52 clipboard support for PuzzlePod TUI.
//!
//! Copies text to the system clipboard via the OSC 52 escape sequence,
//! which works over SSH, tmux, and mosh.

use std::io::Write;

/// Copy text to the system clipboard via OSC 52.
///
/// Writes directly to /dev/tty (not stdout) so it works in alternate screen mode.
pub fn copy_osc52(text: &str) {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = write!(tty, "\x1b]52;c;{}\x07", encoded);
    }
}
