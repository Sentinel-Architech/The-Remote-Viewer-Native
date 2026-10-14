//! trv-android: the Android shell of The Remote Viewer Network.
//!
//! Zero external dependencies. The UI itself lives in `trv-ui` and contains
//! no platform APIs; this crate is only the thin Android adapter:
//! `NativeActivity` entry → looper event loop → software framebuffer blit.
//!
//! Build graph: `trv-android` (cdylib) → `trv-ui` → `trv-core`.
//! See `BUILD.md` for the APK assembly path.

/// Reverse-DNS package id (must match `AndroidManifest.xml`).
pub const PACKAGE: &str = "network.remoteviewer.trv";
/// User-visible app name (must match the manifest label).
pub const APP_NAME: &str = "The Remote Viewer Network";
/// Native library name (must match the manifest `lib_name` meta-data).
pub const LIB_NAME: &str = "trv_android";

pub mod keys;
pub mod widget;

#[cfg(target_os = "android")]
mod app;
#[cfg(target_os = "android")]
mod ffi;

#[cfg(not(target_os = "android"))]
mod host;
#[cfg(not(target_os = "android"))]
pub use host::android_entry_description;
