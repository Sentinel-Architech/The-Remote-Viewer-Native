# BUILD.md — The Remote Viewer Network v0.1 UI shell

## What this is

`trv-ui` — the **portable UI core**. Pure Rust, std only, zero external
dependencies, zero platform APIs. One chat screen (the Sentinel), two
renderings of the same state:

- **Pixel path** — software-renders into a plain RGBA8888 framebuffer
  (own 8×8 bitmap font embedded; no OS fonts, no GPU).
- **Text path** — renders the same screen as plain text lines (for
  character-cell displays / serial terminals).

`trv-android` — the **Android adapter**. `NativeActivity` entry,
hand-rolled NDK FFI (`ffi.rs`), looper event loop (`app.rs`), software
blit via `ANativeWindow_lock`/`unlockAndPost`. No EGL/GLES, no Play
Services, no Gradle. `AndroidManifest.xml` requests **no permissions**.

Build graph: `trv-android` (cdylib) → `trv-ui` → `trv-core` (engine,
untouched).

---

## The portability contract (1980 → tomorrow)

Principle: *whether the device is from 1980 or comes out tomorrow, if it
has a screen and can run code, it can run TRV.* No artificial cutoffs.

To port the UI to a new device, implement **two traits** (~30–60 lines)
from `trv-ui::platform` — nothing else:

```rust
pub trait EventPump {
    fn poll(&mut self) -> Option<UiEvent>;   // Char, Backspace, Enter,
                                             // Escape, Tap(x,y), Scroll,
                                             // Resize(w,h), Quit
}
pub trait PixelTarget {
    fn size(&self) -> (u32, u32);
    fn present(&mut self, pixels: &[u32], w: u32, h: u32); // RGBA8888
}
pub trait TextTarget {
    fn present_text(&mut self, text: &str, cols: u32, rows: u32);
}
```

Then drive a `Screen`:

```rust
let mut screen = SentinelScreen::new("viewer", w, h);
loop {
    if let Some(e) = pump.poll() { screen.on_event(e); }
    // pixel device:
    screen.draw(&mut framebuffer, w, h); target.present(&framebuffer, w, h);
    // -or- text device:
    screen.draw_text(&mut buf, cols, rows); target.present_text(&buf, cols, rows);
}
```

Rules for backends:

- The UI core **never** calls a platform API. All of it lives behind the
  three traits above.
- Pixel format is always logical RGBA8888 (`0xRRGGBBAA`), row-major. The
  backend may downsample/dither (RGB565, 1-bit mono…) — the UI doesn't care.
- Prefer the **software rendering fallback**: blit the framebuffer with
  whatever the device offers (Android: `ANativeWindow`; desktop: window
  canvas or file; framebuffer device: `/dev/fb0`). GPU paths are optional
  enhancements, never requirements.
- Text devices skip pixels entirely and use `draw_text`.

Shipped backends:

| Backend | File | Status |
|---|---|---|
| ANSI terminal (`EventPump`+`TextTarget`, std only) | `ui/src/backends/terminal.rs` | ✅ runs today |
| Android `NativeActivity` (`PixelTarget` via `ANativeWindow`) | `android/src/app.rs` | ✅ code-complete, needs CI build to run |
| iOS / desktop window / wearable / e-ink / serial | — | 🟡 implement the 2 traits |

---

## Building the APK (GitHub Actions — free for public repos)

The APK is assembled **without Gradle**: `cargo` → `aapt2` → `zipalign` →
`apksigner`. All open-source Android SDK command-line tools.

### Required components on the CI runner

- Rust toolchain + targets: `aarch64-linux-android` (Pixel 7),
  optionally `armv7-linux-androideabi`, `x86_64-linux-android`
- Android NDK (r25+, for the clang toolchain + `llvm-strip`)
- Android SDK build-tools (for `aapt2`, `d8`, `zipalign`, `apksigner`;
  `d8` only needed once Java/Kotlin enters the picture — v0.1 has none)
- `ANDROID_NDK_HOME` / `ANDROID_HOME` set; target linker configured,
  e.g. via `.cargo/config.toml`:
  ```toml
  [target.aarch64-linux-android]
  linker = "<NDK>/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang"
  ```

### Assembly steps (per ABI, here `arm64-v8a`)

1. `cargo build --release --target aarch64-linux-android -p trv-android`
   → `target/aarch64-linux-android/release/libtrv_android.so`
2. `aapt2 compile --dir android/res -o /tmp/compiled_res.zip`
   (v0.1: no `res/` dir yet — skip until assets exist)
3. `aapt2 link -o /tmp/base.apk -I android.jar --manifest android/AndroidManifest.xml --min-sdk-version 26 --target-sdk-version 34 --java /tmp/gen`
4. `mkdir -p /tmp/apk/lib/arm64-v8a && cp libtrv_android.so $_`
   `cd /tmp/apk && zip -r /tmp/base.apk .` (add more ABIs the same way)
5. `zipalign -p 4 /tmp/base.apk /tmp/aligned.apk`
6. `apksigner sign --ks debug.keystore --out trv-v0.1.apk /tmp/aligned.apk`
   (v0.1: debug key. Release signing with a hardware-backed key is a
   documented TODO before any public distribution.)
7. Upload `trv-v0.1.apk` as the workflow artifact; `adb install` on Pixel 7.

A ready-to-place workflow is in
[`github-workflow-android.yml`](github-workflow-android.yml) — copy to
`.github/workflows/android.yml` at the repo root when pushing.

---

## Verified vs not-yet-verified (honest ledger)

**Verified on this machine (offline):**

- `cargo check --offline --workspace --all-targets` — 0 warnings, 0 errors.
- `cargo test --offline --workspace` — **190 passed, 0 failed**
  (164 pre-existing + 26 new: 20 `trv-ui`, 5 android keycode, 1 android metadata).
- Android-only modules (`ffi.rs`, `app.rs`) **type-checked** via a shim
  crate that includes them on the host (`cargo check` never links, so the
  raw NDK declarations check cleanly) — 0 warnings.
- The font: rendered the full 95-glyph chart to an image and inspected it
  by eye — legible.
- The screen: rendered `SentinelScreen` to an image and inspected it —
  header, bubbles, input, SEND button all correct.
- The terminal backend: ran `sentinel_term` end-to-end (type → Sentinel
  answers via the MoE router → `/quit`).

**NOT verifiable here — needs the CI build host:**

- Compiling for `aarch64-linux-android` (target + NDK not installed).
- `ANativeActivity_onCreate` actually firing on a device (logic reviewed,
  not executed).
- Soft-keyboard behavior, tap coordinates, DPI scaling on a real Pixel 7.
- The assembled APK installing/launching.

**Known v0.1 gaps (documented, not hidden):**

- Text entry maps basic Latin keycodes only; full IME composition (CJK,
  emoji, swipe) is v0.2.
- Integer UI scaling (`pw/540`, max 4×) keeps text readable on phones;
  true density-independent layout is v0.2.
- Debug signing only; release key management before distribution.
- Single screen (Sentinel chat). Feed, wallet, AR, games plug into the
  same `Screen` trait later — no re-architecture needed.

## Dependencies added

**None.** The workspace remains at zero external Rust dependencies.
Everything above is std + hand-written FFI.
