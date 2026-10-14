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
    cols: u32,
    rows: u32,
}

impl Terminal {
    pub fn new() -> Self {
        // Best-effort terminal size; falls back to 80x24.
        let (cols, rows) = terminal_size().unwrap_or((80, 24));
        Terminal {
            pending: Vec::new(),
            cols,
            rows,
        }
    }

    pub fn size(&self) -> (u32, u32) {
        (self.cols, self.rows)
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
                // Feed chars in order, then Enter. pending is a stack, so
                // push in reverse.
                self.pending.push(UiEvent::Enter);
                for c in line.chars().rev() {
                    self.pending.push(UiEvent::Char(c));
                }
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
        // Clear screen + home cursor.
        let _ = out.write_all(b"\x1b[2J\x1b[H");
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
    }
}

/// Try `$COLUMNS`/`$LINES`, then `stty size`, else `None`.
fn terminal_size() -> Option<(u32, u32)> {
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
