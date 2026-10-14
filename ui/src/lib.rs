//! trv-ui: the portable UI core of The Remote Viewer Network.
//!
//! # The portability contract
//!
//! This crate contains **zero platform APIs**. No window system calls, no
//! input APIs, no GPU, no fonts from the OS, no WebView, nothing corporate.
//! It is pure Rust + std only.
//!
//! A device runs the TRV UI by implementing **two tiny traits** (see
//! [`platform`]):
//!
//! * [`platform::EventPump`] — feed the UI input events (key, tap, resize…).
//! * [`platform::PixelTarget`] and/or [`platform::TextTarget`] — show output.
//!
//! The UI core offers two rendering paths from the same state:
//!
//! * **Pixel path** ([`screen::SentinelScreen::draw`]): software-renders the
//!   whole screen into a plain RGBA8888 framebuffer. The device just blits
//!   the pixels — via `ANativeWindow` on Android, a window canvas on
//!   desktop, or whatever a future (or 1980) device has.
//! * **Text path** ([`screen::SentinelScreen::draw_text`]): renders the same
//!   screen as plain text lines for character-cell displays and terminals.
//!
//! Principle: *whether the device is from 1980 or comes out tomorrow, if it
//! has a screen and can run code, it can run TRV.* No artificial cutoffs.
//! Backends live outside this crate's core logic (see [`backends`]); adding
//! a new device never rewrites the UI.

pub mod backends;
pub mod chat;
pub mod conversations;
pub mod font;
pub mod gated;
pub mod model;
pub mod platform;
pub mod render;
pub mod router;
pub mod screen;
pub mod verify_ui;
