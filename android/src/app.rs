//! Android app: `NativeActivity` entry, looper event loop, software display.
//!
//! * Entry: the manifest points `android.app.NativeActivity` at this
//!   library; Android calls [`ANativeActivity_onCreate`].
//! * Threading: one app thread owns a looper and all UI/render state.
//!   Lifecycle callbacks run on the main thread and only take the state
//!   lock for tiny, non-blocking updates, then wake the looper. The app
//!   thread copies what it needs out from under the lock (a snapshot),
//!   drops the guard, and only then does blocking work
//!   (`ALooper_pollOnce`, `ANativeWindow_lock`) — so a main-thread
//!   callback can never block on the app thread: no ANR, no deadlock.
//!   The one exception is pulling raw events off the input queue, which
//!   happens under the lock but only issues non-blocking
//!   `AInputQueue_*` calls.
//! * Display: pure software rendering. The [`SentinelScreen`] draws into a
//!   CPU framebuffer; we blit it with `ANativeWindow_lock` /
//!   `unlockAndPost`. No EGL, no GLES, no GPU required — this runs on any
//!   Android, including GrapheneOS, and degrades gracefully.
//! * Input: hardware keys, the soft keyboard (summoned by tapping the
//!   input box), and taps. v0.1 maps basic Latin keycodes; full IME
//!   composition is a documented v0.2 step.

use crate::ffi::*;
use crate::keys::{keycode_to_action, KeyAction};
use std::ffi::c_void;
use std::mem;
use std::os::raw::c_int;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, MutexGuard};
use trv_ui::platform::{PixelScreen, Screen, UiEvent};
use trv_ui::screen::SentinelScreen;

const LOOPER_ID_INPUT: c_int = 1;
const LOOPER_ID_CMD: c_int = 2;

/// Command byte sent through the wake pipe.
const CMD_DESTROY: u8 = 1;

/// TRV receipt-issuer public key.
///
/// PLACEHOLDER — this is not a real issuer key and MUST be replaced with
/// the genuine TRV issuer public key before the app accepts any real
/// receipt. Until then every receipt fails verification, entitlements
/// stay `None`, and the paywall gates deny (fail closed).
const ISSUER_PUBKEY: [u8; 32] = [0u8; 32];

/// Read the app's internal data directory from the activity.
///
/// Returns `None` when the activity pointer or the path itself is null,
/// or when the path is not valid UTF-8 — the caller then treats the
/// entitlement as absent (gates deny).
unsafe fn data_path(activity: *mut ANativeActivity) -> Option<std::path::PathBuf> {
    if activity.is_null() {
        return None;
    }
    let raw = (*activity).internal_data_path;
    if raw.is_null() {
        return None;
    }
    let s = std::ffi::CStr::from_ptr(raw).to_str().ok()?;
    Some(std::path::PathBuf::from(s))
}

/// Load the stored entitlement for this install.
///
/// Any failure — no receipt file, unreadable file, forged receipt,
/// expired receipt — yields `None`, and the UI gates fail closed.
fn load_entitlement_for(activity: *mut ANativeActivity) -> Option<trv_backend::entitlement::Entitlement> {
    // SAFETY: `activity` is the valid, never-changing activity pointer
    // snapshotted from shared state; we only read the path field.
    let dir = unsafe { data_path(activity) }?;
    crate::entitlement::load_entitlement(&dir, &ISSUER_PUBKEY)
}

/// Shared between the main thread (callbacks) and the app thread.
struct Shared {
    looper: AtomicPtr<ALooper>,
    /// Handoff state. The mutex is only ever held for tiny, non-blocking
    /// updates — never across `ALooper_pollOnce`, `AInputQueue_*`
    /// (blocking forms), or `ANativeWindow_lock`.
    state: Mutex<State>,
    /// The leaked callbacks box, so a fatal early failure in the app
    /// thread can uninstall and free it. Written once in
    /// `ANativeActivity_onCreate` before the app thread spawns.
    callbacks: *mut ANativeActivityCallbacks,
}

/// State shared with the main thread. Everything the app thread needs
/// long-term for rendering (screen, framebuffer) lives in [`Ui`],
/// owned solely by the app thread.
struct State {
    activity: *mut ANativeActivity,
    looper: *mut ALooper,
    cmd_read: c_int,
    cmd_write: c_int,
    window: *mut ANativeWindow,
    input_queue: *mut AInputQueue,
    input_attached: bool,
    running: bool,
    needs_draw: bool,
}

/// App-thread-owned UI/render state. Only the app thread touches this —
/// never shared with the main thread, so no lock is needed for it.
struct Ui {
    screen: SentinelScreen,
    /// Logical (UI) size and backing framebuffer.
    fb: Vec<u32>,
    fb_w: u32,
    fb_h: u32,
    /// Physical px per UI px (DPI scaling for phones).
    scale: u32,
}

// SAFETY: `Shared` is handed from the main thread to the app thread exactly
// once (as a raw pointer through `std::thread::spawn`). Access protocol:
//   * `looper` is an atomic — lock-free on both threads.
//   * `state` sits behind a mutex that is only ever held for tiny,
//     non-blocking updates; the app thread always drops the guard before
//     any blocking call, so a main-thread callback can never block on it.
//   * `callbacks` is written once in `ANativeActivity_onCreate` before the
//     thread spawns and only read afterwards.
unsafe impl Send for Shared {}

// SAFETY: every raw pointer in `State` is only dereferenced while holding
// the `Shared.state` mutex (short, non-blocking main-thread callbacks) or
// by the app thread from a pointer value copied out from under the mutex —
// never concurrently from both threads. The one pointer the app thread
// keeps across a blocking call (the window) is held via its own
// `ANativeWindow_acquire` reference, so the main thread may release its
// copy (`on_window_destroyed`) mid-frame without a use-after-free.
unsafe impl Send for State {}

impl State {
    fn new(activity: *mut ANativeActivity) -> Self {
        State {
            activity,
            looper: ptr::null_mut(),
            cmd_read: -1,
            cmd_write: -1,
            window: ptr::null_mut(),
            input_queue: ptr::null_mut(),
            input_attached: false,
            running: true,
            needs_draw: true,
        }
    }
}

/// Lock the shared state, recovering from a poisoned mutex instead of
/// panicking: on Android's main thread a panic would kill the process,
/// and the guarded state is still valid and usable.
unsafe fn lock_state<'a>(shared: *mut Shared) -> MutexGuard<'a, State> {
    (*shared).state.lock().unwrap_or_else(|e| e.into_inner())
}

/// Wake the app thread's looper (lock-free; safe from any callback).
unsafe fn wake(shared: *mut Shared) {
    if shared.is_null() {
        return;
    }
    let looper = (*shared).looper.load(Ordering::Acquire);
    if !looper.is_null() {
        ALooper_wake(looper);
    }
}

/// Undo `ANativeActivity_onCreate` after a fatal early failure in the app
/// thread (pipe or looper creation failed): uninstall the callbacks so
/// Android stops calling into dead state, then free both leaked boxes.
/// The OS tears down the activity; there is no app thread left to clean up.
unsafe fn uninstall(shared: *mut Shared) {
    let callbacks = (*shared).callbacks;
    let activity = lock_state(shared).activity;
    if !activity.is_null() {
        (*activity).callbacks = ptr::null_mut();
        (*activity).instance = ptr::null_mut();
    }
    if !callbacks.is_null() {
        drop(Box::from_raw(callbacks));
    }
    drop(Box::from_raw(shared));
}

// ------------------------------------------------------------ callbacks

unsafe extern "C" fn on_resume(a: *mut ANativeActivity) {
    let s = (*a).instance as *mut Shared;
    lock_state(s).needs_draw = true;
    wake(s);
}

unsafe extern "C" fn on_destroy(a: *mut ANativeActivity) {
    let s = (*a).instance as *mut Shared;
    let fd = lock_state(s).cmd_write;
    if fd >= 0 {
        let cmd = CMD_DESTROY;
        write(fd, &cmd as *const u8 as *const c_void, 1);
    }
    // The app thread observes CMD_DESTROY and exits; the OS reclaims the
    // leaked Shared/State afterwards (process-scoped singletons).
}

unsafe extern "C" fn on_window_created(a: *mut ANativeActivity, window: *mut ANativeWindow) {
    let s = (*a).instance as *mut Shared;
    ANativeWindow_acquire(window);
    {
        let mut st = lock_state(s);
        st.window = window;
        st.needs_draw = true;
    }
    wake(s);
}

unsafe extern "C" fn on_window_destroyed(a: *mut ANativeActivity, _w: *mut ANativeWindow) {
    let s = (*a).instance as *mut Shared;
    {
        let mut st = lock_state(s);
        if !st.window.is_null() {
            ANativeWindow_release(st.window);
            st.window = ptr::null_mut();
        }
    }
    wake(s);
}

unsafe extern "C" fn on_redraw_needed(a: *mut ANativeActivity, _w: *mut ANativeWindow) {
    let s = (*a).instance as *mut Shared;
    lock_state(s).needs_draw = true;
    wake(s);
}

unsafe extern "C" fn on_input_created(a: *mut ANativeActivity, queue: *mut AInputQueue) {
    let s = (*a).instance as *mut Shared;
    {
        let mut st = lock_state(s);
        st.input_queue = queue;
        let looper = (*s).looper.load(Ordering::Acquire);
        if !looper.is_null() && !st.input_attached {
            AInputQueue_attachLooper(queue, looper, LOOPER_ID_INPUT, None, ptr::null_mut());
            st.input_attached = true;
        }
    }
    wake(s);
}

unsafe extern "C" fn on_input_destroyed(a: *mut ANativeActivity, _q: *mut AInputQueue) {
    let s = (*a).instance as *mut Shared;
    {
        let mut st = lock_state(s);
        if !st.input_queue.is_null() {
            AInputQueue_detachLooper(st.input_queue);
            st.input_queue = ptr::null_mut();
            st.input_attached = false;
        }
    }
    wake(s);
}

// ---------------------------------------------------------------- input

/// Translate one Android key event into [`UiEvent`]s. Pure function of the
/// event fields — no queue or screen access.
fn key_to_events(action: i32, flags: i32, keycode: i32, meta: i32, out: &mut Vec<UiEvent>) {
    if action != AKEY_EVENT_ACTION_DOWN {
        return;
    }
    if flags & AKEY_EVENT_FLAG_CANCELED != 0 {
        return;
    }
    let shift = meta & AMETA_SHIFT_ON != 0;
    match keycode_to_action(keycode, shift) {
        Some(KeyAction::Char(c)) => out.push(UiEvent::Char(c)),
        Some(KeyAction::Backspace) => out.push(UiEvent::Backspace),
        Some(KeyAction::Enter) => out.push(UiEvent::Enter),
        Some(KeyAction::Escape) => out.push(UiEvent::Escape),
        None => {}
    }
}

/// Pull pending events off the input queue and translate them to
/// [`UiEvent`]s. Taps are reported in logical (UI) pixels.
///
/// Must be called with the state lock held: the queue pointer is only
/// valid until the main thread destroys it, and every `AInputQueue_*`
/// call below is non-blocking, so the lock is never held across a
/// blocking call.
unsafe fn pull_input(queue: *mut AInputQueue, scale: u32) -> Vec<UiEvent> {
    let mut events = Vec::new();
    while AInputQueue_hasEvents(queue) != 0 {
        let mut ev: *mut AInputEvent = ptr::null_mut();
        if AInputQueue_getEvent(queue, &mut ev) < 0 {
            break;
        }
        let mut handled = 1;
        match AInputEvent_getType(ev) {
            t if t == AINPUT_EVENT_TYPE_KEY => {
                let before = events.len();
                key_to_events(
                    AKeyEvent_getAction(ev),
                    AKeyEvent_getFlags(ev),
                    AKeyEvent_getKeyCode(ev),
                    AKeyEvent_getMetaState(ev),
                    &mut events,
                );
                if events.len() == before {
                    handled = 0;
                }
            }
            t if t == AINPUT_EVENT_TYPE_MOTION => {
                if AMotionEvent_getAction(ev) & AMOTION_EVENT_ACTION_MASK
                    == AMOTION_EVENT_ACTION_DOWN
                {
                    let x = (AMotionEvent_getX(ev, 0).max(0.0) as u32) / scale;
                    let y = (AMotionEvent_getY(ev, 0).max(0.0) as u32) / scale;
                    events.push(UiEvent::Tap(x, y));
                }
            }
            _ => handled = 0,
        }
        AInputQueue_finishEvent(queue, ev, handled);
    }
    events
}

/// Drain the input queue into the screen. The queue itself is only touched
/// under the state lock (see [`pull_input`]); translating/applying the
/// events — including the soft-keyboard calls — happens with no lock held.
/// Taps inside the input box summon the soft keyboard.
unsafe fn drain_input(shared: *mut Shared, ui: &mut Ui, activity: *mut ANativeActivity) {
    let events = {
        let st = lock_state(shared);
        let queue = st.input_queue;
        if queue.is_null() {
            return;
        }
        pull_input(queue, ui.scale)
    };
    let mut needs_kb_hide = false;
    for e in events {
        if let UiEvent::Tap(x, y) = e {
            if ui.screen.input_hit(x, y) {
                ANativeActivity_showSoftInput(
                    activity,
                    ANATIVEACTIVITY_SHOW_SOFT_INPUT_IMPLICIT,
                );
            }
        }
        if e == UiEvent::Enter {
            needs_kb_hide = true;
        }
        ui.screen.on_event(e);
    }
    if needs_kb_hide {
        ANativeActivity_hideSoftInput(activity, ANATIVEACTIVITY_HIDE_SOFT_INPUT_IMPLICIT_ONLY);
    }
}

// --------------------------------------------------------------- display

/// Render the screen and blit it to the native window.
///
/// `window` is a reference owned by the caller (acquired before the
/// call); the state lock is NOT held here — `ANativeWindow_lock` blocks.
/// Pixel swizzle: our framebuffer is 0xRRGGBBAA; `WINDOW_FORMAT_RGBA_8888`
/// wants bytes [R,G,B,A] in memory, i.e. the byte-swapped u32 on LE.
unsafe fn render_and_present(window: *mut ANativeWindow, ui: &mut Ui) {
    let pw = ANativeWindow_width(window).max(1) as u32;
    let ph = ANativeWindow_height(window).max(1) as u32;
    ANativeWindow_setBuffersGeometry(window, pw as i32, ph as i32, WINDOW_FORMAT_RGBA_8888);

    // Integer UI scaling so the 8px font stays readable on phone DPIs.
    let scale = (pw / 540).clamp(1, 4);
    let w = pw / scale;
    let h = ph / scale;
    if ui.fb_w != w || ui.fb_h != h {
        ui.scale = scale;
        ui.fb_w = w;
        ui.fb_h = h;
        ui.fb = vec![0; (w * h) as usize];
        ui.screen.on_event(UiEvent::Resize(w, h));
    }

    ui.screen.draw(&mut ui.fb, w, h);

    let mut buf: ANativeWindowBuffer = mem::zeroed();
    if ANativeWindow_lock(window, &mut buf, ptr::null_mut()) != 0 {
        return;
    }
    let dst = buf.bits as *mut u32;
    if !dst.is_null() {
        let stride = buf.stride.max(1) as usize;
        let bw = (buf.width.max(1) as u32).min(pw) as usize;
        let bh = (buf.height.max(1) as u32).min(ph) as usize;
        for y in 0..bh {
            // Nearest-neighbor upscale from the logical framebuffer.
            let sy = (y as u32 / scale).min(h - 1) as usize;
            for x in 0..bw {
                let sx = (x as u32 / scale).min(w - 1) as usize;
                *dst.add(y * stride + x) = ui.fb[sy * w as usize + sx].swap_bytes();
            }
        }
    }
    ANativeWindow_unlockAndPost(window);
}

// ------------------------------------------------------------ main loop

/// Pointer-sized snapshot copied out from under the state lock.
struct Snap {
    running: bool,
    window: *mut ANativeWindow,
    cmd_read: c_int,
}

unsafe fn android_main(shared: *mut Shared) {
    // Best-effort: refresh the widget's data file so the home-screen
    // widget shows live numbers. Fails silently (returns false) on any
    // error — the widget falls back to its baked-in snapshot — and never
    // panics, so startup can't break here.
    crate::widget::write_widget_snapshot();

    let mut fds = [0 as c_int; 2];
    if pipe(fds.as_mut_ptr()) != 0 {
        // No wake pipe, no loop: uninstall everything and bail instead
        // of leaking the callbacks and Shared.
        uninstall(shared);
        return;
    }
    let looper = ALooper_prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS);
    if looper.is_null() {
        close(fds[0]);
        close(fds[1]);
        uninstall(shared);
        return;
    }
    ALooper_acquire(looper);
    ALooper_addFd(
        looper,
        fds[0],
        LOOPER_ID_CMD,
        ALOOPER_EVENT_INPUT,
        None,
        ptr::null_mut(),
    );
    (*shared).looper.store(looper, Ordering::Release);

    // App-thread-owned UI state: never shared with the main thread, so no
    // lock is needed to touch it.
    let mut ui = Ui {
        screen: SentinelScreen::new("viewer", 360, 640),
        fb: Vec::new(),
        fb_w: 0,
        fb_h: 0,
        scale: 2,
    };

    // `activity` never changes after onCreate; snapshot it once.
    let activity = lock_state(shared).activity;

    // Paywall: verify the stored receipt (if any). No receipt, a forged
    // receipt, or an expired receipt → None → the UnlimitedEi and
    // messaging gates deny (fail closed).
    ui.screen.set_entitlement(load_entitlement_for(activity));

    {
        let mut st = lock_state(shared);
        st.looper = looper;
        st.cmd_read = fds[0];
        st.cmd_write = fds[1];
        // An input queue may have arrived before the looper existed.
        if !st.input_queue.is_null() && !st.input_attached {
            AInputQueue_attachLooper(
                st.input_queue,
                looper,
                LOOPER_ID_INPUT,
                None,
                ptr::null_mut(),
            );
            st.input_attached = true;
        }
        st.needs_draw = true;
    }

    loop {
        // 1. Snapshot under the lock; the guard is dropped immediately.
        //    Take our own window reference so the main thread can release
        //    its copy (on_window_destroyed) mid-frame without a
        //    use-after-free.
        let snap = {
            let st = lock_state(shared);
            let window = st.window;
            if !window.is_null() {
                ANativeWindow_acquire(window);
            }
            Snap {
                running: st.running,
                window,
                cmd_read: st.cmd_read,
            }
        };
        if !snap.running {
            if !snap.window.is_null() {
                ANativeWindow_release(snap.window);
            }
            break;
        }

        // 2. Block indefinitely with NO lock held: callbacks wake us via
        //    ALooper_wake and can never block on us (no ANR, no deadlock).
        let mut out_fd = 0 as c_int;
        let mut out_events = 0 as c_int;
        let mut out_data: *mut c_void = ptr::null_mut();
        let ident = ALooper_pollOnce(-1, &mut out_fd, &mut out_events, &mut out_data);

        // 3. Handle the event with no lock held.
        let mut mark_draw = false;
        let mut quit = false;
        match ident {
            LOOPER_ID_INPUT => {
                drain_input(shared, &mut ui, activity);
                mark_draw = true;
            }
            LOOPER_ID_CMD => {
                let mut cmd = 0u8;
                let n = read(snap.cmd_read, &mut cmd as *mut u8 as *mut c_void, 1);
                if n == 1 && cmd == CMD_DESTROY {
                    quit = true;
                }
                mark_draw = true;
            }
            id if id == ALOOPER_POLL_WAKE => {
                mark_draw = true;
            }
            id if id == ALOOPER_POLL_TIMEOUT => {}
            id if id == ALOOPER_POLL_CALLBACK => {}
            id if id == ALOOPER_POLL_ERROR => {}
            _ => {}
        }

        // 4. Re-lock only to publish results.
        let draw = {
            let mut st = lock_state(shared);
            if quit {
                st.running = false;
            }
            if mark_draw {
                st.needs_draw = true;
            }
            let draw = st.needs_draw || ui.fb.is_empty();
            st.needs_draw = false;
            draw
        };

        // 5. Render with no lock held (`ANativeWindow_lock` blocks), then
        //    release our window reference.
        if draw && !snap.window.is_null() {
            render_and_present(snap.window, &mut ui);
        }
        if !snap.window.is_null() {
            ANativeWindow_release(snap.window);
        }
    }

    // Teardown: short lock, no blocking calls.
    {
        let mut st = lock_state(shared);
        if !st.input_queue.is_null() {
            AInputQueue_detachLooper(st.input_queue);
            st.input_queue = ptr::null_mut();
        }
        if !st.window.is_null() {
            ANativeWindow_release(st.window);
            st.window = ptr::null_mut();
        }
        if st.cmd_read >= 0 {
            close(st.cmd_read);
        }
        if st.cmd_write >= 0 {
            close(st.cmd_write);
        }
        st.looper = ptr::null_mut();
    }
    (*shared).looper.store(ptr::null_mut(), Ordering::Release);
    ALooper_release(looper);
}

/// NativeActivity entry point, called by Android on launch.
#[no_mangle]
pub unsafe extern "C" fn ANativeActivity_onCreate(
    activity: *mut ANativeActivity,
    _saved_state: *mut c_void,
    _saved_state_size: usize,
) {
    let shared = Box::into_raw(Box::new(Shared {
        looper: AtomicPtr::new(ptr::null_mut()),
        state: Mutex::new(State::new(activity)),
        callbacks: ptr::null_mut(),
    }));
    (*activity).instance = shared as *mut c_void;

    let callbacks = Box::new(ANativeActivityCallbacks {
        on_start: None,
        on_resume: Some(on_resume),
        on_save_instance_state: None,
        on_pause: None,
        on_stop: None,
        on_destroy: Some(on_destroy),
        on_window_focus_changed: None,
        on_native_window_created: Some(on_window_created),
        on_native_window_destroyed: Some(on_window_destroyed),
        on_native_window_redraw_needed: Some(on_redraw_needed),
        on_native_window_resized: None,
        on_input_queue_created: Some(on_input_created),
        on_input_queue_destroyed: Some(on_input_destroyed),
        on_content_rect_changed: None,
        on_configuration_changed: None,
        on_low_memory: None,
    });
    (*activity).callbacks = Box::into_raw(callbacks);
    // Remember the box so a fatal early failure in the app thread can
    // uninstall and free it. Written before the thread spawns.
    (*shared).callbacks = (*activity).callbacks;
    // (Both boxes are leaked on purpose: they live as long as the
    // activity, and the app thread frees them on clean exit paths.)

    // `shared` crosses threads as a raw pointer (see the SAFETY notes on
    // the Send impls): the app thread owns `Shared`, and the main thread
    // only touches it inside the short, non-blocking callbacks above.
    let raw = shared as usize;
    std::thread::spawn(move || android_main(raw as *mut Shared));
}
