//! The Sentinel chat screen — the v0.1 main (and only) screen.
//!
//! One screen, two renderings of the same state: [`SentinelScreen`] draws
//! into pixels ([`PixelScreen`](crate::platform::PixelScreen)) and into
//! plain text ([`TextScreen`](crate::platform::TextScreen)). Layout is
//! computed once from the drawable size and shared by both paths, so a
//! text-mode device and a 4K display show the same conversation.

use crate::font::{GLYPH_H, GLYPH_W};
use crate::model::{Author, ChatSession};
use crate::platform::{PixelScreen, Screen, TextScreen, UiEvent};
use crate::render::{self, color};

/// Pixel layout of the chat screen, derived from the drawable size.
#[derive(Debug, Clone, Copy)]
struct Layout {
    w: u32,
    h: u32,
    header_h: u32,
    input_h: u32,
    send_w: u32,
    pad: u32,
}

impl Layout {
    fn new(w: u32, h: u32) -> Self {
        Layout {
            w,
            h,
            header_h: 28,
            input_h: 32,
            send_w: 72,
            pad: 8,
        }
    }

    fn msg_top(&self) -> u32 {
        self.header_h + self.pad
    }

    fn msg_bottom(&self) -> u32 {
        self.h.saturating_sub(self.input_h + self.pad * 2)
    }

    fn input_y(&self) -> u32 {
        self.h.saturating_sub(self.input_h + self.pad)
    }

    fn send_rect(&self) -> (u32, u32, u32, u32) {
        let x = self.w.saturating_sub(self.send_w + self.pad);
        (x, self.input_y(), self.send_w, self.input_h)
    }

    fn input_rect(&self) -> (u32, u32, u32, u32) {
        let (sx, _, _, _) = self.send_rect();
        (self.pad, self.input_y(), sx.saturating_sub(self.pad * 2), self.input_h)
    }

    /// Max message-bubble width in pixels.
    fn bubble_max_w(&self) -> u32 {
        self.w.saturating_sub(self.pad * 4).min(560).max(64)
    }
}

/// The v0.1 main screen: a chat with the on-device Sentinel.
pub struct SentinelScreen {
    chat: ChatSession,
    scroll: u32, // lines scrolled up from the bottom
    w: u32,
    h: u32,
}

impl SentinelScreen {
    pub fn new(owner_handle: &str, w: u32, h: u32) -> Self {
        SentinelScreen {
            chat: ChatSession::new(owner_handle),
            scroll: 0,
            w: w.max(64),
            h: h.max(64),
        }
    }

    pub fn chat(&self) -> &ChatSession {
        &self.chat
    }

    /// True when a tap at logical `(x, y)` lands inside the input box.
    /// Backends use this to summon the on-screen keyboard.
    pub fn input_hit(&self, x: u32, y: u32) -> bool {
        let (ix, iy, iw, ih) = self.layout().input_rect();
        x >= ix && x < ix + iw && y >= iy && y < iy + ih
    }

    fn layout(&self) -> Layout {
        Layout::new(self.w, self.h)
    }

    fn submit(&mut self) {
        if self.chat.submit() {
            self.scroll = 0; // new answer: jump to bottom
        }
    }

    /// All wrapped message lines, oldest first: (author, line).
    fn wrapped_lines(&self, max_cells: u32) -> Vec<(Author, String)> {
        let mut out = Vec::new();
        for m in self.chat.messages() {
            let prefix = match m.author {
                Author::You => "you: ",
                Author::Sentinel => "sentinel: ",
            };
            for line in render::wrap_text(&format!("{prefix}{}", m.text), max_cells) {
                out.push((m.author, line));
            }
        }
        out
    }

    /// Visible slice of wrapped lines given the scroll offset.
    fn visible_lines(&self, max_cells: u32, max_lines: u32) -> Vec<(Author, String)> {
        let lines = self.wrapped_lines(max_cells);
        let total = lines.len() as u32;
        let n = max_lines.min(total);
        // scroll=0 shows the tail; scroll=k moves k lines up.
        let end = total.saturating_sub(self.scroll).min(total);
        let start = end.saturating_sub(n);
        lines[start as usize..end as usize].to_vec()
    }

    fn clamp_scroll(&mut self, max_cells: u32, max_lines: u32) {
        let total = self.wrapped_lines(max_cells).len() as u32;
        let max_scroll = total.saturating_sub(max_lines.min(total));
        self.scroll = self.scroll.min(max_scroll);
    }
}

impl Screen for SentinelScreen {
    fn on_event(&mut self, event: UiEvent) {
        let lay = self.layout();
        // Cell/line geometry used by scroll clamping.
        let max_cells = render::cells_for(lay.bubble_max_w()).max(8);
        let max_lines = lay
            .msg_bottom()
            .saturating_sub(lay.msg_top())
            .saturating_sub(GLYPH_H)
            / GLYPH_H;
        match event {
            UiEvent::Char(c) => {
                if !c.is_control() {
                    self.chat.push_input(c);
                }
            }
            UiEvent::Backspace => self.chat.pop_input(),
            UiEvent::Enter => self.submit(),
            UiEvent::Escape => self.chat.clear_input(),
            UiEvent::Scroll(d) => {
                if d < 0 {
                    self.scroll = self.scroll.saturating_add((-d) as u32);
                } else {
                    self.scroll = self.scroll.saturating_sub(d as u32);
                }
                self.clamp_scroll(max_cells, max_lines.max(1));
            }
            UiEvent::Tap(x, y) => {
                let (sx, sy, sw, sh) = lay.send_rect();
                if x >= sx && x < sx + sw && y >= sy && y < sy + sh {
                    self.submit();
                }
            }
            UiEvent::Resize(w, h) => {
                self.w = w.max(64);
                self.h = h.max(64);
                self.scroll = 0;
            }
            UiEvent::Quit => {}
        }
    }
}

impl PixelScreen for SentinelScreen {
    fn draw(&self, fb: &mut [u32], w: u32, h: u32) {
        // Graceful no-op on an undersized framebuffer: a library draw path
        // must never panic on bad caller input.
        if fb.len() < (w as usize).saturating_mul(h as usize) {
            return;
        }
        let lay = Layout::new(w, h);
        // Background.
        render::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // Header.
        render::fill_rect(fb, w, h, 0, 0, w, lay.header_h, color::PANEL);
        render::fill_rect(fb, w, h, 0, lay.header_h - 1, w, 1, color::PANEL_EDGE);
        render::draw_text(fb, w, h, lay.pad + 2, 10, "THE SENTINEL", color::ACCENT);
        let sub = "on-device";
        let sub_x = w.saturating_sub((sub.len() as u32) * GLYPH_W + lay.pad + 2);
        render::draw_text(fb, w, h, sub_x, 10, sub, color::DIM);

        // Messages.
        let max_cells = render::cells_for(lay.bubble_max_w()).max(8);
        let area_h = lay.msg_bottom().saturating_sub(lay.msg_top());
        let max_lines = area_h / GLYPH_H;
        let mut y = lay.msg_top() + 4;
        for (author, line) in self.visible_lines(max_cells, max_lines.max(1)) {
            if y + GLYPH_H > lay.msg_bottom() {
                break;
            }
            let bubble_c = match author {
                Author::You => color::YOU_BUBBLE,
                Author::Sentinel => color::SENT_BUBBLE,
            };
            let text_w = (line.chars().count() as u32) * GLYPH_W;
            let bw = text_w + 16;
            let bx = match author {
                Author::You => w.saturating_sub(bw + lay.pad),
                Author::Sentinel => lay.pad,
            };
            render::fill_rect(fb, w, h, bx, y, bw, GLYPH_H + 6, bubble_c);
            render::draw_text(fb, w, h, bx + 8, y + 3, &line, color::TEXT);
            y += GLYPH_H + 10;
        }

        // Input box.
        let (ix, iy, iw, ih) = lay.input_rect();
        render::fill_rect(fb, w, h, ix, iy, iw, ih, color::INPUT_BG);
        render::fill_rect(fb, w, h, ix, iy, iw, 1, color::PANEL_EDGE);
        render::fill_rect(fb, w, h, ix, iy + ih - 1, iw, 1, color::PANEL_EDGE);
        let prompt = "> ";
        let mut tx = render::draw_text(fb, w, h, ix + 8, iy + 12, prompt, color::DIM);
        let max_input_cells = render::cells_for(iw.saturating_sub(16)).max(1);
        let input: String = self.chat.input().chars().rev().take(max_input_cells as usize).collect::<String>().chars().rev().collect();
        tx = render::draw_text(fb, w, h, tx, iy + 12, &input, color::TEXT);
        // Cursor block.
        render::fill_rect(fb, w, h, tx + 2, iy + 12, 6, GLYPH_H, color::ACCENT);

        // Send button.
        let (sx, sy, sw, sh) = lay.send_rect();
        render::fill_rect(fb, w, h, sx, sy, sw, sh, color::SEND_BG);
        let label = "SEND";
        let lx = sx + (sw.saturating_sub((label.len() as u32) * GLYPH_W)) / 2;
        render::draw_text(fb, w, h, lx, sy + 12, label, color::BLACK);
    }
}

impl TextScreen for SentinelScreen {
    fn draw_text(&self, out: &mut dyn core::fmt::Write, cols: u32, rows: u32) {
        let cols = cols.max(20);
        let rows = rows.max(8);
        let _ = writeln!(out, "== THE SENTINEL (on-device) ==");
        let max_lines = rows.saturating_sub(4);
        for (author, line) in self.visible_lines(cols, max_lines) {
            let tag = match author {
                Author::You => "you",
                Author::Sentinel => "sen",
            };
            let _ = writeln!(out, "[{tag}] {line}");
        }
        let _ = writeln!(out, "{}", "-".repeat(cols as usize));
        let _ = write!(out, "> {}", self.chat.input());
        let _ = writeln!(out);
        let _ = writeln!(out, "[type + Enter to send]");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{Screen, UiEvent};

    fn type_text(s: &mut SentinelScreen, text: &str) {
        for c in text.chars() {
            s.on_event(UiEvent::Char(c));
        }
    }

    #[test]
    fn enter_submits_and_answers() {
        let mut s = SentinelScreen::new("viewer", 640, 400);
        type_text(&mut s, "hello");
        s.on_event(UiEvent::Enter);
        assert_eq!(s.chat().messages().len(), 3); // greeting + you + sentinel
        assert!(s.chat().input().is_empty());
    }

    #[test]
    fn tap_send_button_submits() {
        let mut s = SentinelScreen::new("viewer", 640, 400);
        type_text(&mut s, "hi");
        let lay = s.layout();
        let (sx, sy, sw, sh) = lay.send_rect();
        s.on_event(UiEvent::Tap(sx + sw / 2, sy + sh / 2));
        assert_eq!(s.chat().messages().len(), 3);
    }

    #[test]
    fn tap_outside_send_does_nothing() {
        let mut s = SentinelScreen::new("viewer", 640, 400);
        type_text(&mut s, "hi");
        s.on_event(UiEvent::Tap(10, 200));
        assert_eq!(s.chat().messages().len(), 1);
    }

    #[test]
    fn draw_paints_nonempty_framebuffer() {
        let s = SentinelScreen::new("viewer", 320, 200);
        let mut fb = vec![0u32; 320 * 200];
        s.draw(&mut fb, 320, 200);
        let painted = fb.iter().filter(|&&p| p != 0).count();
        assert!(painted > 1000, "expected painted pixels, got {painted}");
    }

    #[test]
    fn draw_with_tiny_framebuffer_does_not_panic() {
        let s = SentinelScreen::new("viewer", 320, 200);
        let mut fb = vec![0u32; 10]; // far too small: must no-op, not panic
        s.draw(&mut fb, 320, 200);
        assert!(fb.iter().all(|&p| p == 0));
    }

    #[test]
    fn draw_text_renders_conversation() {
        let mut s = SentinelScreen::new("viewer", 320, 200);
        type_text(&mut s, "hello");
        s.on_event(UiEvent::Enter);
        let mut out = String::new();
        s.draw_text(&mut out, 60, 24);
        assert!(out.contains("THE SENTINEL"));
        assert!(out.contains("hello"));
    }

    #[test]
    fn scroll_clamps_to_content() {
        let mut s = SentinelScreen::new("viewer", 640, 400);
        s.on_event(UiEvent::Scroll(-1000));
        // Must not panic; scroll clamps.
        let mut fb = vec![0u32; 640 * 400];
        s.draw(&mut fb, 640, 400);
    }

    #[test]
    fn resize_resets_view() {
        let mut s = SentinelScreen::new("viewer", 640, 400);
        s.on_event(UiEvent::Resize(320, 200));
        let mut fb = vec![0u32; 320 * 200];
        s.draw(&mut fb, 320, 200);
    }
}
