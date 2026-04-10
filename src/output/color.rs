use std::sync::atomic::{AtomicBool, Ordering};

static NO_COLOR: AtomicBool = AtomicBool::new(false);

pub fn disable_color() {
    NO_COLOR.store(true, Ordering::Relaxed);
}

fn color_enabled() -> bool {
    !NO_COLOR.load(Ordering::Relaxed)
}

/// ANSI color codes.
pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const CYAN: &str = "\x1b[36m";

/// Wrap text with color, respecting --no-color.
pub fn color(code: &str, text: &str) -> String {
    if color_enabled() {
        format!("{}{}{}", code, text, RESET)
    } else {
        text.to_string()
    }
}

/// Bold text.
pub fn bold(text: &str) -> String {
    color(BOLD, text)
}

/// Green (success/selected).
pub fn green(text: &str) -> String {
    color(GREEN, text)
}

/// Yellow (warning).
pub fn yellow(text: &str) -> String {
    color(YELLOW, text)
}

/// Red (error/high severity).
pub fn red(text: &str) -> String {
    color(RED, text)
}

/// Cyan (info).
pub fn cyan(text: &str) -> String {
    color(CYAN, text)
}

/// Dim (duplicates, low-importance).
pub fn dim(text: &str) -> String {
    color(DIM, text)
}
