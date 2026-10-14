//! Render the full embedded font as a PPM image for visual inspection.
//!
//! ```sh
//! cargo run --offline -p trv-ui --example font_chart
//! # writes /tmp/trv_font_chart.ppm
//! ```
//! Verifies every glyph is legible with human eyes, not just unit tests.

use std::io::Write;
use trv_ui::font::{glyph_for, GLYPH_H, GLYPH_W};
use trv_ui::render::{self, color};

fn main() {
    let cols = 16u32;
    let rows = 6u32; // 16*6 = 96 cells >= 95 glyphs
    let cell = 2u32; // px scale per font pixel
    let pad = 4u32;
    let label_h = 12u32;
    let cw = GLYPH_W * cell + pad * 2;
    let chh = GLYPH_H * cell + pad * 2 + label_h;
    let w = cols * cw + pad;
    let h = rows * chh + pad;
    let mut fb = vec![color::BLACK; (w * h) as usize];

    for i in 0u32..95 {
        let ch = char::from_u32(32 + i).unwrap();
        let cx = (i % cols) * cw + pad;
        let cy = (i / cols) * chh + pad;
        // Cell background for non-space.
        if ch != ' ' {
            render::fill_rect(&mut fb, w, h, cx, cy, cw - pad, chh - pad, color::PANEL);
        }
        // Scaled glyph.
        let g = glyph_for(ch);
        for (r, bits) in g.iter().enumerate() {
            for c in 0..8u32 {
                if (bits >> (7 - c)) & 1 == 1 {
                    let px = cx + pad + c * cell;
                    let py = cy + pad + r as u32 * cell;
                    render::fill_rect(&mut fb, w, h, px, py, cell, cell, color::TEXT);
                }
            }
        }
        // Codepoint label.
        let label = format!("{i:02}");
        render::draw_text(
            &mut fb,
            w,
            h,
            cx + pad,
            cy + pad + GLYPH_H * cell + 2,
            &label,
            color::DIM,
        );
    }

    // Write binary PPM (P6).
    let mut f = std::fs::File::create("/tmp/trv_font_chart.ppm").unwrap();
    f.write_all(format!("P6\n{w} {h}\n255\n").as_bytes()).unwrap();
    for px in &fb {
        let r = ((px >> 24) & 0xFF) as u8;
        let g = ((px >> 16) & 0xFF) as u8;
        let b = ((px >> 8) & 0xFF) as u8;
        f.write_all(&[r, g, b]).unwrap();
    }
    println!("wrote /tmp/trv_font_chart.ppm ({w}x{h})");
}
