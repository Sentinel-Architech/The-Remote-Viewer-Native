//! Raw FFI to the Android NDK C APIs we use. No ndk crates, no JNI —
//! just the stable C surface: `native_activity.h`, `native_window.h`,
//! `looper.h`, `input.h`, plus `pipe`/`read`/`write` from bionic.
//!
//! Compiled only for `target_os = "android"`. Everything here is a
//! declaration; `cargo check` never links, so this module is fully
//! type-checked on any host.

use std::ffi::c_void;
use std::os::raw::{c_char, c_float, c_int};

// ---------------------------------------------------------------- looper.h

pub type ALooper = c_void;

pub const ALOOPER_PREPARE_ALLOW_NON_CALLBACKS: c_int = 1;
pub const ALOOPER_EVENT_INPUT: c_int = 1;

pub const ALOOPER_POLL_WAKE: c_int = -1;
pub const ALOOPER_POLL_CALLBACK: c_int = -2;
pub const ALOOPER_POLL_TIMEOUT: c_int = -3;
pub const ALOOPER_POLL_ERROR: c_int = -4;

pub type ALooperCallback =
    Option<unsafe extern "C" fn(fd: c_int, events: c_int, data: *mut c_void) -> c_int>;

// ------------------------------------------------------ native_window.h

pub type ANativeWindow = c_void;

pub const WINDOW_FORMAT_RGBA_8888: c_int = 1;

#[repr(C)]
pub struct ARect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

#[repr(C)]
pub struct ANativeWindowBuffer {
    pub width: i32,
    pub height: i32,
    pub stride: i32,
    pub format: i32,
    pub bits: *mut c_void,
    pub reserved: [*mut c_void; 6],
}

// ----------------------------------------------------------- input.h

pub type AInputQueue = c_void;
pub type AInputEvent = c_void;

pub const AINPUT_EVENT_TYPE_KEY: i32 = 1;
pub const AINPUT_EVENT_TYPE_MOTION: i32 = 2;

pub const AKEY_EVENT_ACTION_DOWN: i32 = 0;
pub const AKEY_EVENT_FLAG_CANCELED: i32 = 0x20;

pub const AMETA_SHIFT_ON: i32 = 0x01;

pub const AMOTION_EVENT_ACTION_MASK: i32 = 0xff;
pub const AMOTION_EVENT_ACTION_DOWN: i32 = 0;

// Keycodes live in `keys.rs` (unit-tested); this module only declares
// functions and structs from the NDK headers.

// --------------------------------------------------- native_activity.h

#[repr(C)]
pub struct ANativeActivityCallbacks {
    pub on_start: AActivityCallback,
    pub on_resume: AActivityCallback,
    pub on_save_instance_state:
        Option<unsafe extern "C" fn(*mut ANativeActivity, *mut usize) -> *mut c_void>,
    pub on_pause: AActivityCallback,
    pub on_stop: AActivityCallback,
    pub on_destroy: AActivityCallback,
    pub on_window_focus_changed: Option<unsafe extern "C" fn(*mut ANativeActivity, c_int)>,
    pub on_native_window_created:
        Option<unsafe extern "C" fn(*mut ANativeActivity, *mut ANativeWindow)>,
    pub on_native_window_destroyed:
        Option<unsafe extern "C" fn(*mut ANativeActivity, *mut ANativeWindow)>,
    pub on_native_window_redraw_needed:
        Option<unsafe extern "C" fn(*mut ANativeActivity, *mut ANativeWindow)>,
    pub on_native_window_resized:
        Option<unsafe extern "C" fn(*mut ANativeActivity, *mut ANativeWindow)>,
    pub on_input_queue_created:
        Option<unsafe extern "C" fn(*mut ANativeActivity, *mut AInputQueue)>,
    pub on_input_queue_destroyed:
        Option<unsafe extern "C" fn(*mut ANativeActivity, *mut AInputQueue)>,
    pub on_content_rect_changed:
        Option<unsafe extern "C" fn(*mut ANativeActivity, *const ARect)>,
    pub on_configuration_changed: AActivityCallback,
    pub on_low_memory: AActivityCallback,
}

pub type AActivityCallback = Option<unsafe extern "C" fn(*mut ANativeActivity)>;

#[repr(C)]
pub struct ANativeActivity {
    pub callbacks: *mut ANativeActivityCallbacks,
    pub vm: *mut c_void,
    pub env: *mut c_void,
    pub clazz: *mut c_void,
    pub internal_data_path: *const c_char,
    pub external_data_path: *const c_char,
    pub sdk_version: i32,
    pub instance: *mut c_void,
    pub asset_manager: *mut c_void,
    pub obb_path: *const c_char,
}

// ------------------------------------------------------------------ bionic

extern "C" {
    pub fn pipe(fds: *mut c_int) -> c_int;
    pub fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    pub fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    pub fn close(fd: c_int) -> c_int;
}

extern "C" {
    pub fn ALooper_prepare(opts: c_int) -> *mut ALooper;
    pub fn ALooper_acquire(looper: *mut ALooper);
    pub fn ALooper_release(looper: *mut ALooper);
    pub fn ALooper_pollOnce(
        timeout_millis: c_int,
        out_fd: *mut c_int,
        out_events: *mut c_int,
        out_data: *mut *mut c_void,
    ) -> c_int;
    pub fn ALooper_wake(looper: *mut ALooper);
    pub fn ALooper_addFd(
        looper: *mut ALooper,
        fd: c_int,
        ident: c_int,
        events: c_int,
        callback: ALooperCallback,
        data: *mut c_void,
    ) -> c_int;
}

extern "C" {
    pub fn ANativeWindow_setBuffersGeometry(
        window: *mut ANativeWindow,
        width: i32,
        height: i32,
        format: i32,
    ) -> i32;
    pub fn ANativeWindow_lock(
        window: *mut ANativeWindow,
        out_buffer: *mut ANativeWindowBuffer,
        in_out_dirty_bounds: *mut ARect,
    ) -> i32;
    pub fn ANativeWindow_unlockAndPost(window: *mut ANativeWindow) -> i32;
    pub fn ANativeWindow_acquire(window: *mut ANativeWindow);
    pub fn ANativeWindow_release(window: *mut ANativeWindow);
    pub fn ANativeWindow_width(window: *mut ANativeWindow) -> i32;
    pub fn ANativeWindow_height(window: *mut ANativeWindow) -> i32;
}

extern "C" {
    pub fn AInputQueue_attachLooper(
        queue: *mut AInputQueue,
        looper: *mut ALooper,
        ident: c_int,
        callback: ALooperCallback,
        data: *mut c_void,
    );
    pub fn AInputQueue_detachLooper(queue: *mut AInputQueue);
    pub fn AInputQueue_hasEvents(queue: *mut AInputQueue) -> i32;
    pub fn AInputQueue_getEvent(
        queue: *mut AInputQueue,
        out_event: *mut *mut AInputEvent,
    ) -> i32;
    pub fn AInputQueue_finishEvent(queue: *mut AInputQueue, event: *mut AInputEvent, handled: i32);
    pub fn AInputEvent_getType(event: *const AInputEvent) -> i32;
    pub fn AKeyEvent_getAction(event: *const AInputEvent) -> i32;
    pub fn AKeyEvent_getFlags(event: *const AInputEvent) -> i32;
    pub fn AKeyEvent_getKeyCode(event: *const AInputEvent) -> i32;
    pub fn AKeyEvent_getMetaState(event: *const AInputEvent) -> i32;
    pub fn AMotionEvent_getAction(event: *const AInputEvent) -> i32;
    pub fn AMotionEvent_getX(event: *const AInputEvent, pointer_index: usize) -> c_float;
    pub fn AMotionEvent_getY(event: *const AInputEvent, pointer_index: usize) -> c_float;
}

extern "C" {
    pub fn ANativeActivity_showSoftInput(activity: *mut ANativeActivity, flags: u32);
    pub fn ANativeActivity_hideSoftInput(activity: *mut ANativeActivity, flags: u32);
}

#[allow(dead_code)]
pub const ANATIVEACTIVITY_SHOW_SOFT_INPUT_IMPLICIT: u32 = 0x01;
#[allow(dead_code)]
pub const ANATIVEACTIVITY_SHOW_SOFT_INPUT_FORCED: u32 = 0x02;
#[allow(dead_code)]
pub const ANATIVEACTIVITY_HIDE_SOFT_INPUT_IMPLICIT_ONLY: u32 = 0x01;
#[allow(dead_code)]
pub const ANATIVEACTIVITY_HIDE_SOFT_INPUT_NOT_ALWAYS: u32 = 0x02;
