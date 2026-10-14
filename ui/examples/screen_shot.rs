//! Render the Sentinel chat screen to a PPM for visual inspection.
//!
//! ```sh
//! cargo run --offline -p trv-ui --example screen_shot
//! # writes /tmp/trv_screen.ppm
//! ```

use std::io::Write;
use trv_ui::platform::{PixelScreen, Screen, UiEvent};
use trv_ui::screen::SentinelScreen;

fn main() {
    let w = 480u32;
    let h = 320u32;
    let mut s = SentinelScreen::new("viewer", w, h);
    // Simulate a short conversation.
    for c in "what can you do?".chars() {
        s.on_event(UiEvent::Char(c));
    }
    s.on_event(UiEvent::Enter);
    for c in "tell me about the network".chars() {
        s.on_event(UiEvent::Char(c));
    }

    let mut fb = vec![0u32; (w * h) as usize];
    s.draw(&mut fb, w, h);

    let mut f = std::fs::File::create("/tmp/trv_screen.ppm").unwrap();
    f.write_all(format!("P6\n{w} {h}\n255\n").as_bytes()).unwrap();
    for px in &fb {
        f.write_all(&[
            ((px >> 24) & 0xFF) as u8,
            ((px >> 16) & 0xFF) as u8,
            ((px >> 8) & 0xFF) as u8,
        ])
        .unwrap();
    }
    println!("wrote /tmp/trv_screen.ppm ({w}x{h})");
}
