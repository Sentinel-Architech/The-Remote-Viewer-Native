//! The portability contract: the ONLY surface a device must implement.
//!
//! Everything the UI core needs from a device is here. No window-system
//! types, no OS handles — just events in and pixels/text out. A new device
//! target implements [`EventPump`] plus [`PixelTarget`] and/or
//! [`TextTarget`] (about 30–60 lines), wires them to a [`Screen`], and the
//! whole TRV UI runs unmodified.

/// Input events the UI understands. Backends translate native input
/// (touch, mouse, keys, buttons, …) into these; the UI core never sees the
/// native forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiEvent {
    /// A typed character (from keyboard, IME, or on-screen keyboard).
    Char(char),
    /// Delete the character before the cursor.
    Backspace,
    /// Submit / activate (Enter key, "send" IME action, …).
    Enter,
    /// Leave the current state (Escape / back button).
    Escape,
    /// Pointer or finger tap at pixel coordinates.
    Tap(u32, u32),
    /// Drawable size changed (rotation, window resize, …).
    Resize(u32, u32),
    /// Scroll the message list (wheel, two-finger drag, d-pad, …).
    Scroll(i32),
    /// The app should exit its main loop.
    Quit,
}

/// Feeds [`UiEvent`]s to the UI. Returns `None` when no event is pending
/// (backends may block briefly or return immediately — their choice).
pub trait EventPump {
    fn poll(&mut self) -> Option<UiEvent>;
}

/// Shows a software-rendered frame. Pixels are RGBA8888, row-major, top row
/// first: `pixels[y * w + x]`, `0xRRGGBBAA`.
///
/// The backend owns the real display and may downsample or dither to fit
/// it (e.g. RGB565, or 1-bit mono on the humblest screens) — the UI core
/// always speaks this one logical format.
pub trait PixelTarget {
    /// Current drawable size in pixels.
    fn size(&self) -> (u32, u32);
    /// Display one finished frame.
    fn present(&mut self, pixels: &[u32], w: u32, h: u32);
}

/// Shows the text-mode rendering of the UI (for character-cell displays,
/// serial terminals, and anything without addressable pixels).
pub trait TextTarget {
    /// Display one finished text frame; `cols`/`rows` are the text grid.
    fn present_text(&mut self, text: &str, cols: u32, rows: u32);
}

/// A UI screen: pure state machine over [`UiEvent`]. Implemented by the UI
/// core, driven by backends. Never touches platform APIs.
pub trait Screen {
    fn on_event(&mut self, event: UiEvent);
}

/// A [`Screen`] that software-renders into a pixel framebuffer.
pub trait PixelScreen: Screen {
    fn draw(&self, fb: &mut [u32], w: u32, h: u32);
}

/// A [`Screen`] that renders as plain text for character-cell devices.
pub trait TextScreen: Screen {
    fn draw_text(&self, out: &mut dyn core::fmt::Write, cols: u32, rows: u32);
}
