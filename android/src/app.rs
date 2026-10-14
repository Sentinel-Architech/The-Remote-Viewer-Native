//! Android app: `NativeActivity` entry, looper event loop, software display.
//!
//! * Entry: the manifest points `android.app.NativeActivity` at this
//!   library; Android calls [`ANativeActivity_onCreate`].
//! * Threading: one app thread owns a looper. Lifecycle callbacks run on
//!   the main thread and only take the state lock for tiny updates, then
//!   wake the looper — no lock is ever held across a blocking call.
//! * Display: pure software rendering. The [`SentinelScreen`] draws into a
//!   CPU framebuffer; we blit it with `ANativeWindow_lock` /
//!   `unlockAndPost`. No EGL, no GLES, no GPU required — this runs on any
//!   Android, including GrapheneOS, and degrades gracefully.
//! * Input: hardware keys, the soft keyboard (summoned by tapping the
//!   input box), and taps. v0.1 maps basic Latin keycodes; full IME
//!   composition is a documented v0.2 step.

use crate::ffi::*;
use crate::keys::{keycode_to_action, KeyAction, KEYCODE_BACK};
use std::ffi::c_void;
use std::mem;
use std::os::raw::c_int;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;
use trv_ui::platform::{PixelScreen, Screen, UiEvent};
use trv_ui::screen::SentinelScreen;

const LOOPER_ID_INPUT: c_int = 1;
const LOOPER_ID_CMD: c_int = 2;

/// Command byte sent through the wake pipe.
const CMD_DESTROY: u8 = 1;

/// Shared between the main thread (callbacks) and the app thread.
struct Shared {
    looper: AtomicPtr<ALooper>,
    app: Mutex<App>,
}

struct App {
    activity: *mut ANativeActivity,
    looper: *mut ALooper,
    cmd_read: c_int,
    cmd_write: c_int,
    window: *mut ANativeWindow,
    input_queue: *mut AInputQueue,
    input_attached: bool,
    screen: SentinelScreen,
    /// Logical (UI) size and backing framebuffer.
    fb: Vec<u32>,
    fb_w: u32,
    fb_h: u32,
    /// Physical px per UI px (DPI scaling for phones).
    scale: u32,
    running: bool,
    needs_draw: bool,
}

// Raw pointers are only touched under the mutex or on the app thread.
unsafe impl Send for App {}
unsafe impl Send for Shared {}

impl App {
    fn new(activity: *mut ANativeActivity) -> Self {
        App {
            activity,
            looper: ptr::null_mut(),
            cmd_read: -1,
            cmd_write: -1,
            window: ptr::null_mut(),
            input_queue: ptr::null_mut(),
            input_attached: false,
            screen: SentinelScreen::new("viewer", 360, 640),
            fb: Vec::new(),
            fb_w: 0,
            fb_h: 0,
            scale: 2,
            running: true,
            needs_draw: true,
        }
    }
}

/// Wake the app thread's looper (lock-free; safe from any callback).
unsafe fn wake(shared: *mut Shared) {
    let looper = (*shared).looper.load(Ordering::Acquire);
    if !looper.is_null() {
        ALooper_wake(looper);
    }
}

// ------------------------------------------------------------ callbacks

unsafe extern "C" fn on_start(_a: *mut ANativeActivity) {}
unsafe extern "C" fn on_resume(a: *mut ANativeActivity) {
    let s = (*a).instance as *mut Shared;
    (*s).app.lock().unwrap().needs_draw = true;
    wake(s);
}
unsafe extern "C" fn on_pause(_a: *mut ANativeActivity) {}
unsafe extern "C" fn on_stop(_a: *mut ANativeActivity) {}

unsafe extern "C" fn on_destroy(a: *mut ANativeActivity) {
    let s = (*a).instance as *mut Shared;
    let fd = (*s).app.lock().unwrap().cmd_write;
    if fd >= 0 {
        let cmd = CMD_DESTROY;
        write(fd, &cmd as *const u8 as *const c_void, 1);
    }
    // The app thread observes CMD_DESTROY and exits; the OS reclaims the
    // leaked Shared/App afterwards (process-scoped singletons).
}

unsafe extern "C" fn on_window_created(a: *mut ANativeActivity, window: *mut ANativeWindow) {
    let s = (*a).instance as *mut Shared;
    ANativeWindow_acquire(window);
    {
        let mut app = (*s).app.lock().unwrap();
        app.window = window;
        app.needs_draw = true;
    }
    wake(s);
}

unsafe extern "C" fn on_window_destroyed(a: *mut ANativeActivity, _w: *mut ANativeWindow) {
    let s = (*a).instance as *mut Shared;
    {
        let mut app = (*s).app.lock().unwrap();
        if !app.window.is_null() {
            ANativeWindow_release(app.window);
            app.window = ptr::null_mut();
        }
    }
    wake(s);
}

unsafe extern "C" fn on_redraw_needed(a: *mut ANativeActivity, _w: *mut ANativeWindow) {
    let s = (*a).instance as *mut Shared;
    (*s).app.lock().unwrap().needs_draw = true;
    wake(s);
}

unsafe extern "C" fn on_input_created(a: *mut ANativeActivity, queue: *mut AInputQueue) {
    let s = (*a).instance as *mut Shared;
    {
        let mut app = (*s).app.lock().unwrap();
        app.input_queue = queue;
        let looper = (*s).looper.load(Ordering::Acquire);
        if !looper.is_null() && !app.input_attached {
            AInputQueue_attachLooper(queue, looper, LOOPER_ID_INPUT, None, ptr::null_mut());
            app.input_attached = true;
        }
    }
    wake(s);
}

unsafe extern "C" fn on_input_destroyed(a: *mut ANativeActivity, _q: *mut AInputQueue) {
    let s = (*a).instance as *mut Shared;
    {
        let mut app = (*s).app.lock().unwrap();
        if !app.input_queue.is_null() {
            AInputQueue_detachLooper(app.input_queue);
            app.input_queue = ptr::null_mut();
            app.input_attached = false;
        }
    }
    wake(s);
}

// ---------------------------------------------------------------- input

/// Translate one Android key event into [`UiEvent`]s.
unsafe fn key_to_events(event: *const AInputEvent, out: &mut Vec<UiEvent>) {
    if AKeyEvent_getAction(event) != AKEY_EVENT_ACTION_DOWN {
        return;
    }
    if AKeyEvent_getFlags(event) & AKEY_EVENT_FLAG_CANCELED != 0 {
        return;
    }
    let keycode = AKeyEvent_getKeyCode(event);
    let shift = AKeyEvent_getMetaState(event) & AMETA_SHIFT_ON != 0;
    match keycode_to_action(keycode, shift) {
        Some(KeyAction::Char(c)) => out.push(UiEvent::Char(c)),
        Some(KeyAction::Backspace) => out.push(UiEvent::Backspace),
        Some(KeyAction::Enter) => out.push(UiEvent::Enter),
        Some(KeyAction::Escape) => out.push(UiEvent::Escape),
        None => {}
    }
}

/// Drain the input queue into [`UiEvent`]s. Taps inside the input box also
/// summon the soft keyboard.
unsafe fn drain_input(app: &mut App) {
    let queue = app.input_queue;
    if queue.is_null() {
        return;
    }
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
                key_to_events(ev, &mut events);
                if events.len() == before {
                    handled = 0;
                }
            }
            t if t == AINPUT_EVENT_TYPE_MOTION => {
                if AMotionEvent_getAction(ev) & AMOTION_EVENT_ACTION_MASK
                    == AMOTION_EVENT_ACTION_DOWN
                {
                    let x = (AMotionEvent_getX(ev, 0).max(0.0) as u32) / app.scale;
                    let y = (AMotionEvent_getY(ev, 0).max(0.0) as u32) / app.scale;
                    if app.screen.input_hit(x, y) {
                        ANativeActivity_showSoftInput(
                            app.activity,
                            ANATIVEACTIVITY_SHOW_SOFT_INPUT_IMPLICIT,
                        );
                    }
                    events.push(UiEvent::Tap(x, y));
                }
            }
            _ => handled = 0,
        }
        AInputQueue_finishEvent(queue, ev, handled);
    }
    let mut needs_kb_hide = false;
    for e in events {
        if e == UiEvent::Enter {
            needs_kb_hide = true;
        }
        app.screen.on_event(e);
    }
    if needs_kb_hide {
        ANativeActivity_hideSoftInput(app.activity, ANATIVEACTIVITY_HIDE_SOFT_INPUT_IMPLICIT_ONLY);
    }
    let _ = KEYCODE_BACK; // (documented) back key maps to Escape via keys.rs
}

// --------------------------------------------------------------- display

/// Render the screen and blit it to the native window.
/// Pixel swizzle: our framebuffer is 0xRRGGBBAA; `WINDOW_FORMAT_RGBA_8888`
/// wants bytes [R,G,B,A] in memory, i.e. the byte-swapped u32 on LE.
unsafe fn render_and_present(app: &mut App) {
    let win = app.window;
    if win.is_null() {
        return;
    }
    let pw = ANativeWindow_width(win).max(1) as u32;
    let ph = ANativeWindow_height(win).max(1) as u32;
    ANativeWindow_setBuffersGeometry(win, pw as i32, ph as i32, WINDOW_FORMAT_RGBA_8888);

    // Integer UI scaling so the 8px font stays readable on phone DPIs.
    let scale = (pw / 540).clamp(1, 4).max(1);
    let w = pw / scale;
    let h = ph / scale;
    if app.fb_w != w || app.fb_h != h {
        app.scale = scale;
        app.fb_w = w;
        app.fb_h = h;
        app.fb = vec![0; (w * h) as usize];
        app.screen.on_event(UiEvent::Resize(w, h));
    }

    app.screen.draw(&mut app.fb, w, h);

    let mut buf: ANativeWindowBuffer = mem::zeroed();
    if ANativeWindow_lock(win, &mut buf, ptr::null_mut()) != 0 {
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
                *dst.add(y * stride + x) = app.fb[sy * w as usize + sx].swap_bytes();
            }
        }
    }
    ANativeWindow_unlockAndPost(win);
}

// ------------------------------------------------------------ main loop

unsafe fn android_main(shared: *mut Shared) {
    let mut fds = [0 as c_int; 2];
    if pipe(fds.as_mut_ptr()) != 0 {
        return;
    }
    let looper = ALooper_prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS);
    if looper.is_null() {
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
    {
        let mut app = (*shared).app.lock().unwrap();
        app.looper = looper;
        app.cmd_read = fds[0];
        app.cmd_write = fds[1];
        // An input queue may have arrived before the looper existed.
        if !app.input_queue.is_null() && !app.input_attached {
            AInputQueue_attachLooper(
                app.input_queue,
                looper,
                LOOPER_ID_INPUT,
                None,
                ptr::null_mut(),
            );
            app.input_attached = true;
        }
        app.needs_draw = true;
    }

    loop {
        {
            let app = (*shared).app.lock().unwrap();
            if !app.running {
                break;
            }
        }
        // Block indefinitely: callbacks wake us via ALooper_wake. The lock
        // is never held across this call, so callbacks can't deadlock.
        let mut out_fd = 0 as c_int;
        let mut out_events = 0 as c_int;
        let mut out_data: *mut c_void = ptr::null_mut();
        let ident = ALooper_pollOnce(-1, &mut out_fd, &mut out_events, &mut out_data);

        let mut app = (*shared).app.lock().unwrap();
        if !app.running {
            break;
        }
        match ident {
            LOOPER_ID_INPUT => {
                drain_input(&mut app);
                app.needs_draw = true;
            }
            LOOPER_ID_CMD => {
                let mut cmd = 0u8;
                let n = read(
                    app.cmd_read,
                    &mut cmd as *mut u8 as *mut c_void,
                    1,
                );
                if n == 1 && cmd == CMD_DESTROY {
                    app.running = false;
                }
                app.needs_draw = true;
            }
            id if id == ALOOPER_POLL_WAKE => {
                app.needs_draw = true;
            }
            id if id == ALOOPER_POLL_TIMEOUT => {}
            id if id == ALOOPER_POLL_CALLBACK => {}
            id if id == ALOOPER_POLL_ERROR => {}
            _ => {}
        }
        if !app.window.is_null() && (app.needs_draw || app.fb.is_empty()) {
            app.needs_draw = false;
            render_and_present(&mut app);
        }
    }

    // Teardown.
    {
        let mut app = (*shared).app.lock().unwrap();
        if !app.input_queue.is_null() {
            AInputQueue_detachLooper(app.input_queue);
            app.input_queue = ptr::null_mut();
        }
        if !app.window.is_null() {
            ANativeWindow_release(app.window);
            app.window = ptr::null_mut();
        }
        if app.cmd_read >= 0 {
            close(app.cmd_read);
        }
        if app.cmd_write >= 0 {
            close(app.cmd_write);
        }
        app.looper = ptr::null_mut();
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
        app: Mutex::new(App::new(activity)),
    }));
    (*activity).instance = shared as *mut c_void;

    let callbacks = Box::new(ANativeActivityCallbacks {
        on_start: Some(on_start),
        on_resume: Some(on_resume),
        on_save_instance_state: None,
        on_pause: Some(on_pause),
        on_stop: Some(on_stop),
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
    // (Leaked on purpose: they live as long as the activity.)

    // `shared` crosses threads as a `usize`: raw pointers are not `Send`.
    // Safety rests on the access protocol, not the type system — the app
    // thread owns `Shared` (mutex-guarded state + atomic looper), and the
    // main thread only touches it inside the short, non-blocking callbacks.
    let raw = shared as usize;
    std::thread::spawn(move || android_main(raw as *mut Shared));
}
