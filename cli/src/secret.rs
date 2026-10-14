//! Secret handling helpers for the CLI: no-echo stdin reads and
//! best-effort memory wiping. std only — no external dependencies.
//!
//! Operator secrets (issuer seeds, vault passphrases) must never appear in
//! argv (visible via `ps`, shell history, audit logs) and should be wiped
//! from RAM as soon as they are no longer needed. Wiping is best-effort:
//! the compiler and OS may retain copies outside our control, but we
//! eliminate every copy we can reach.

use std::io::{self, Write};

/// Best-effort wipe of a byte buffer: volatile writes so the compiler
/// cannot optimize the zeroing away.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, uniquely-borrowed byte; zero is always valid.
        unsafe {
            core::ptr::write_volatile(b, 0u8);
        }
    }
}

/// Best-effort wipe of a `String`'s bytes in place (length/capacity kept,
/// contents zeroed). The string must not be used afterwards.
pub fn wipe_string(s: &mut String) {
    // SAFETY: zero bytes are valid UTF-8, so the String stays valid;
    // the caller must not use the string after wiping.
    unsafe {
        for b in s.as_bytes_mut().iter_mut() {
            core::ptr::write_volatile(b, 0u8);
        }
    }
}

/// A 32-byte secret that wipes itself on drop. Use for issuer seeds and
/// other key material held briefly on the stack.
pub struct SecretSeed(pub [u8; 32]);

impl Drop for SecretSeed {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

// ---------------------------------------------------------------------------
// No-echo stdin reads (Unix termios; graceful fallback elsewhere)
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod tty {
    use std::io::Write;
    use std::os::raw::{c_int, c_ulong};
    use std::os::unix::io::AsRawFd;

    /// Linux `struct termios` layout (glibc; same on all architectures for
    /// the fields we touch). Only used for TCGETS/TCSETS around ECHO.
    #[repr(C)]
    struct Termios {
        c_iflag: u32,
        c_oflag: u32,
        c_cflag: u32,
        c_lflag: u32,
        c_line: u8,
        c_cc: [u8; 32],
        c_ispeed: u32,
        c_ospeed: u32,
    }

    extern "C" {
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    }

    const TCGETS: c_ulong = 0x5401;
    const TCSETS: c_ulong = 0x5402;
    const ECHO: u32 = 0x0000_0008;

    /// Disable ECHO on stdin. Returns the previous `c_lflag` for restore,
    /// or `None` when stdin is not a TTY (piped input is not echoed anyway).
    pub fn echo_disable() -> Option<u32> {
        // SAFETY: zeroed Termios is a valid bit pattern; ioctl with
        // TCGETS/TCSETS and a valid fd + termios pointer is well-defined.
        unsafe {
            let fd = std::io::stdin().as_raw_fd();
            let mut t: Termios = std::mem::zeroed();
            if ioctl(fd, TCGETS, &mut t) != 0 {
                return None; // not a TTY (or no termios): nothing to hide
            }
            let prev = t.c_lflag;
            t.c_lflag &= !ECHO;
            if ioctl(fd, TCSETS, &t) != 0 {
                return None;
            }
            Some(prev)
        }
    }

    /// Restore the `c_lflag` saved by [`echo_disable`].
    pub fn echo_restore(prev_lflag: u32) {
        // SAFETY: same contract as echo_disable.
        unsafe {
            let fd = std::io::stdin().as_raw_fd();
            let mut t: Termios = std::mem::zeroed();
            if ioctl(fd, TCGETS, &mut t) == 0 {
                t.c_lflag = prev_lflag;
                ioctl(fd, TCSETS, &t);
            }
        }
        let _ = std::io::stderr().flush();
    }
}

#[cfg(not(unix))]
mod tty {
    /// No termios off Unix: cannot disable echo; piped reads are unaffected.
    /// Callers still get the secret off argv, which is the critical fix.
    pub fn echo_disable() -> Option<u32> {
        None
    }

    #[allow(dead_code)] // used on unix; kept for a uniform call site
    pub fn echo_restore(_prev_lflag: u32) {}
}

/// Read one secret line from stdin without terminal echo.
///
/// - The prompt goes to stderr (stdout stays clean for piping).
/// - On a Unix TTY, ECHO is disabled while reading and restored after,
///   even if the read fails. A newline is printed afterwards so the next
///   output starts on a fresh line.
/// - On piped stdin (or non-Unix), the line is read as-is; piped input
///   is not echoed by the terminal anyway.
/// - The trailing newline is stripped. The caller owns wiping the result.
pub fn read_secret_line(prompt: &str) -> io::Result<String> {
    let _ = io::stderr().write_all(prompt.as_bytes());
    let _ = io::stderr().flush();

    let prev = tty::echo_disable();

    let mut line = String::new();
    let r = io::stdin().read_line(&mut line);

    if let Some(p) = prev {
        tty::echo_restore(p);
        // The hidden input left the cursor at the prompt; move on.
        let _ = io::stderr().write_all(b"\n");
        let _ = io::stderr().flush();
    }

    r?;
    let len = line.trim_end_matches(['\n', '\r']).len();
    line.truncate(len);
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_zeroes_buffer() {
        let mut buf = [0xAAu8; 32];
        wipe(&mut buf);
        assert_eq!(buf, [0u8; 32]);
    }

    #[test]
    fn wipe_string_zeroes_contents() {
        let mut s = String::from("supersecret");
        let len = s.len();
        wipe_string(&mut s);
        assert_eq!(s.len(), len);
        assert!(s.bytes().all(|b| b == 0));
    }

    #[test]
    fn echo_disable_no_tty_returns_none() {
        // Under `cargo test` stdin is not a TTY, so this must be None
        // (and must not panic or alter anything).
        assert_eq!(tty::echo_disable(), None);
    }
}
