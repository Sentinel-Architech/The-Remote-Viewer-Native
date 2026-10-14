//! Run the Sentinel chat UI in a plain terminal.
//!
//! ```sh
//! cargo run --offline -p trv-ui --example sentinel_term
//! ```
//! Type a line + Enter to talk to the on-device Sentinel. `/quit` exits.
//! This is the desktop proof that the UI core has zero platform APIs:
//! the same `SentinelScreen` also renders to raw pixels for Android.

use trv_ui::backends::terminal::{terminal_size, Terminal};
use trv_ui::platform::{EventPump, Screen, TextScreen, TextTarget, UiEvent};
use trv_ui::screen::SentinelScreen;

fn main() {
    let mut term = Terminal::new();
    let (cols, rows) = terminal_size().unwrap_or((80, 24));
    let mut screen = SentinelScreen::new("viewer", 640, 400);

    let mut buf = String::new();
    buf.clear();
    screen.draw_text(&mut buf, cols, rows);
    term.present_text(&buf, cols, rows);

    loop {
        match term.poll() {
            None => continue,
            Some(UiEvent::Quit) => break,
            Some(e) => {
                screen.on_event(e);
                buf.clear();
                screen.draw_text(&mut buf, cols, rows);
                term.present_text(&buf, cols, rows);
            }
        }
    }
    println!("Sentinel offline. Everything stayed on this device.");
}
