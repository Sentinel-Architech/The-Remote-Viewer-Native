//! ANSI terminal backend: [`EventPump`] + [`TextTarget`] over stdin/stdout.
//!
//! Std only. Line-based input (no raw-mode termios tricks, so it works on
//! any terminal — including a serial console on 1980 hardware). The screen
//! is fully redrawn after every submitted line.

use crate::platform::{EventPump, TextTarget, UiEvent};
use std::io::{self, Write};

/// Stdin/stdout terminal adapter.
pub struct Terminal {
    pending: Vec<UiEvent>,
}

impl Terminal {
    pub fn new() -> Self {
        Terminal {
            pending: Vec::new(),
        }
    }

    /// Queue one input line's events: chars in order, then Enter.
    /// `pending` is a stack, so push in reverse.
    fn queue_line(&mut self, line: &str) {
        self.pending.push(UiEvent::Enter);
        for c in line.chars().rev() {
            self.pending.push(UiEvent::Char(c));
        }
    }
}

impl Default for Terminal {
    fn default() -> Self {
        Self::new()
    }
}

impl EventPump for Terminal {
    fn poll(&mut self) -> Option<UiEvent> {
        if let Some(e) = self.pending.pop() {
            return Some(e);
        }
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => Some(UiEvent::Quit), // EOF
            Ok(_) => {
                let line = line.trim_end_matches(&['\r', '\n'][..]);
                if line == "/quit" {
                    return Some(UiEvent::Quit);
                }
                self.queue_line(line);
                self.pending.pop()
            }
            Err(_) => Some(UiEvent::Quit),
        }
    }
}

impl TextTarget for Terminal {
    fn present_text(&mut self, text: &str, _cols: u32, _rows: u32) {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        write_frame(&mut out, text);
    }
}

/// Clear the screen, home the cursor, then write one text frame. Split
/// out from [`TextTarget::present_text`] so it can be unit-tested against
/// a byte buffer instead of real stdout.
fn write_frame(out: &mut dyn Write, text: &str) {
    let _ = out.write_all(b"\x1b[2J\x1b[H");
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}

/// Best-effort terminal size probe: `$COLUMNS`/`$LINES`, then `stty
/// size`, else `None`. Public so text-grid drivers can size themselves
/// without shelling out on their own.
pub fn terminal_size() -> Option<(u32, u32)> {
    if let (Ok(c), Ok(r)) = (
        std::env::var("COLUMNS").map(|v| v.parse::<u32>()),
        std::env::var("LINES").map(|v| v.parse::<u32>()),
    ) {
        if let (Ok(c), Ok(r)) = (c, r) {
            if c >= 20 && r >= 8 {
                return Some((c, r));
            }
        }
    }
    // `stty size` prints "rows cols".
    let probe = std::process::Command::new("stty")
        .arg("size")
        .stdin(std::process::Stdio::inherit())
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&probe.stdout);
    let mut it = s.split_whitespace();
    let r: u32 = it.next()?.parse().ok()?;
    let c: u32 = it.next()?.parse().ok()?;
    if c >= 20 && r >= 8 {
        Some((c, r))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_feeds_chars_in_order_then_enter() {
        let mut t = Terminal::new();
        t.queue_line("ab");
        assert_eq!(t.poll(), Some(UiEvent::Char('a')));
        assert_eq!(t.poll(), Some(UiEvent::Char('b')));
        assert_eq!(t.poll(), Some(UiEvent::Enter));
    }

    #[test]
    fn poll_empty_line_feeds_just_enter() {
        let mut t = Terminal::new();
        t.queue_line("");
        assert_eq!(t.poll(), Some(UiEvent::Enter));
    }

    #[test]
    fn write_frame_clears_screen_then_writes_text() {
        let mut buf = Vec::new();
        write_frame(&mut buf, "hi");
        assert_eq!(buf, b"\x1b[2J\x1b[Hhi");
    }

    #[test]
    fn terminal_size_env_handling() {
        // `$COLUMNS`/`$LINES` are process-global: cover every env case in
        // this one test so parallel test threads can't interleave
        // mutations, and restore the original values afterwards.
        let old_c = std::env::var("COLUMNS").ok();
        let old_l = std::env::var("LINES").ok();

        // Sane values win outright.
        std::env::set_var("COLUMNS", "100");
        std::env::set_var("LINES", "30");
        assert_eq!(terminal_size(), Some((100, 30)));

        // Too small: rejected, falls through to the `stty` probe (no tty
        // under cargo test, so the tiny values must not come back).
        std::env::set_var("COLUMNS", "10");
        assert_ne!(terminal_size(), Some((10, 30)));

        // Garbage: rejected as well; whatever comes back must be sane.
        std::env::set_var("COLUMNS", "wide");
        std::env::set_var("LINES", "tall");
        assert!(terminal_size().map_or(true, |(c, r)| c >= 20 && r >= 8));

        match old_c {
            Some(v) => std::env::set_var("COLUMNS", v),
            None => std::env::remove_var("COLUMNS"),
        }
        match old_l {
            Some(v) => std::env::set_var("LINES", v),
            None => std::env::remove_var("LINES"),
        }
    }
}
