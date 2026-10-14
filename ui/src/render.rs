//! Software rasterizer: the GPU-free rendering path.
//!
//! Everything draws into a plain `&mut [u32]` RGBA8888 framebuffer with
//! integer math. No GPU, no shaders, no OS drawing calls — this is the
//! fallback that lets TRV run on any device with addressable pixels,
//! from 1980 to tomorrow.

use crate::font::{glyph_for, GLYPH_W};

/// RGBA8888 color helpers.
pub mod color {
    /// Pack r,g,b,a bytes into one `u32` pixel.
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> u32 {
        ((r as u32) << 24) | ((g as u32) << 16) | ((b as u32) << 8) | (a as u32)
    }

    pub const BLACK: u32 = rgba(8, 10, 16, 255);
    pub const PANEL: u32 = rgba(18, 24, 38, 255);
    pub const PANEL_EDGE: u32 = rgba(46, 64, 100, 255);
    pub const TEXT: u32 = rgba(232, 238, 248, 255);
    pub const DIM: u32 = rgba(140, 152, 175, 255);
    pub const ACCENT: u32 = rgba(64, 190, 178, 255); // TRV teal
    pub const YOU_BUBBLE: u32 = rgba(28, 52, 84, 255);
    pub const SENT_BUBBLE: u32 = rgba(24, 32, 48, 255);
    pub const INPUT_BG: u32 = rgba(14, 18, 30, 255);
    pub const SEND_BG: u32 = rgba(32, 110, 102, 255);
}

/// Fill a rectangle, clipped to the framebuffer.
pub fn fill_rect(fb: &mut [u32], w: u32, h: u32, x: u32, y: u32, rw: u32, rh: u32, c: u32) {
    let x1 = x.min(w);
    let y1 = y.min(h);
    let x2 = (x + rw).min(w);
    let y2 = (y + rh).min(h);
    for py in y1..y2 {
        let base = (py * w) as usize;
        for px in x1..x2 {
            fb[base + px as usize] = c;
        }
    }
}

/// Draw one glyph cell at `(x, y)`; clipped per-pixel.
pub fn draw_glyph(fb: &mut [u32], w: u32, h: u32, x: u32, y: u32, ch: char, c: u32) {
    let g = glyph_for(ch);
    for (row, bits) in g.iter().enumerate() {
        let py = y + row as u32;
        if py >= h {
            break;
        }
        for col in 0..8u32 {
            if (bits >> (7 - col)) & 1 == 1 {
                let px = x + col;
                if px < w {
                    fb[(py * w + px) as usize] = c;
                }
            }
        }
    }
}

/// Draw text left-to-right; returns the x position after the last glyph.
pub fn draw_text(fb: &mut [u32], w: u32, h: u32, mut x: u32, y: u32, s: &str, c: u32) -> u32 {
    for ch in s.chars() {
        if x + GLYPH_W > w {
            break;
        }
        draw_glyph(fb, w, h, x, y, ch, c);
        x += GLYPH_W;
    }
    x
}

/// How many glyph cells fit in `px` pixels.
pub fn cells_for(px: u32) -> u32 {
    px / GLYPH_W
}

/// Word-wrap `s` into lines of at most `max_cells` glyph cells.
/// Long words are hard-broken. Newlines in `s` are honored.
pub fn wrap_text(s: &str, max_cells: u32) -> Vec<String> {
    let max = max_cells.max(1) as usize;
    let mut lines = Vec::new();
    for para in s.split('\n') {
        let mut cur = String::new();
        for word in para.split(' ') {
            if word.is_empty() {
                continue;
            }
            // Split into max-sized chunks (hard-breaks long words).
            let chars: Vec<char> = word.chars().collect();
            let mut start = 0;
            while start < chars.len() {
                let end = (start + max).min(chars.len());
                let chunk: String = chars[start..end].iter().collect();
                let need = if cur.is_empty() {
                    chunk.chars().count()
                } else {
                    cur.chars().count() + 1 + chunk.chars().count()
                };
                if need > max {
                    lines.push(core::mem::take(&mut cur));
                }
                if !cur.is_empty() {
                    cur.push(' ');
                }
                cur.push_str(&chunk);
                start = end;
            }
        }
        lines.push(cur);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_rect_clips() {
        let mut fb = vec![0u32; 4 * 4];
        fill_rect(&mut fb, 4, 4, 2, 2, 10, 10, 0xFF00FF00);
        assert_eq!(fb[2 * 4 + 2], 0xFF00FF00);
        assert_eq!(fb[3 * 4 + 3], 0xFF00FF00);
        assert_eq!(fb[0], 0);
        assert_eq!(fb[1 * 4 + 1], 0);
    }

    #[test]
    fn text_draws_pixels() {
        let mut fb = vec![0u32; 64 * 16];
        draw_text(&mut fb, 64, 16, 0, 0, "Hi", color::TEXT);
        assert!(fb.iter().any(|&p| p != 0));
    }

    #[test]
    fn wrap_respects_width() {
        let lines = wrap_text("aa bb cc dd", 5);
        for l in &lines {
            assert!(l.chars().count() <= 5, "line too long: {l}");
        }
        assert!(lines.len() >= 2);
    }

    #[test]
    fn wrap_breaks_long_words() {
        let lines = wrap_text("abcdefghij", 4);
        assert_eq!(lines, vec!["abcd", "efgh", "ij"]);
    }

    #[test]
    fn wrap_honors_newlines() {
        let lines = wrap_text("a\nb", 10);
        assert_eq!(lines, vec!["a", "b"]);
    }
}
