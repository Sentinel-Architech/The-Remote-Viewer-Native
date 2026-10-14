//! Host-side stub: documents what the Android entry does.
//!
//! On a real device this module is compiled out and `app` (the
//! `NativeActivity` glue) is compiled in. It exists so the crate stays
//! meaningful — and checkable — on every host.

/// What `ANativeActivity_onCreate` (see `app.rs`) sets up on Android.
pub fn android_entry_description() -> &'static str {
    "ANativeActivity_onCreate installs lifecycle/input/window callbacks, \
     spawns the looper thread, and runs the portable SentinelScreen: \
     software-rendered via ANativeWindow, input via AInputQueue."
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{APP_NAME, LIB_NAME, PACKAGE};

    #[test]
    fn package_metadata_is_sane() {
        assert_eq!(PACKAGE, "network.remoteviewer.trv");
        assert_eq!(APP_NAME, "The Remote Viewer Network");
        assert_eq!(LIB_NAME, "trv_android");
        assert!(android_entry_description().contains("ANativeActivity_onCreate"));
    }
}
