//! Attempt throttling for abuse-prone backend entry points.
//!
//! Thin, honest integration over `trv_core::ratelimit::RateLimiter` —
//! see the `trv-core` crate docs for the sliding-window + ban mechanics
//! this wraps. This backend has no request handler of its own, so this
//! module is the documented hook, not an active guard.
//!
//! ## Intended integration points
//!
//! - [`crate::activation::redeem`]/[`crate::activation::validate`]:
//!   online code-guessing. An attacker with the public code format can
//!   otherwise brute-force checksums one code at a time; the throttle
//!   turns that into a bounded number of attempts per caller id.
//! - [`crate::registration::Registration::new`]: account-creation spam.
//!   A script can otherwise mint unbounded ghost registrations; the
//!   throttle caps how many new-account attempts a caller id may make
//!   in the window.
//!
//! ## Who supplies the caller id
//!
//! The `caller_id` key is intentionally opaque — a device id, account
//! id, or source IP, chosen at the adapter layer. The adapter layer is
//! the future network front (the CLI server or the Android/JNI bridge)
//! that sits between the network and these local-first functions; it
//! knows who the caller is and must supply that id on every check.
//! Local callers that have no network peer should NOT share one global
//! id, or all local attempts will throttle each other.
//!
//! No logic is changed by this module: [`AttemptThrottle::check`]
//! returns `true` when the caller may proceed, `false` when they must
//! be turned away. Wiring it into the entry points above is a future
//! adapter-layer step.

use std::time::Duration;

use trv_core::ratelimit::RateLimiter;

/// Per-caller attempt throttle wrapping [`RateLimiter`].
///
/// Keys on a caller-supplied id string (device id / IP, supplied by
/// the adapter layer). Not thread-safe by itself; wrap in a `Mutex` if
/// shared across threads, mirroring the underlying limiter.
#[derive(Debug)]
pub struct AttemptThrottle {
    limiter: RateLimiter,
}

impl AttemptThrottle {
    /// Default throttle: 100 attempts/second per caller id, 60-second
    /// bans, 100k tracked ids. Tuned for request-scale traffic; choose
    /// [`AttemptThrottle::with_limits`] for stricter abuse gates.
    pub fn new() -> Self {
        AttemptThrottle {
            limiter: RateLimiter::new(),
        }
    }

    /// Throttle with explicit limits: `threshold` attempts per 1-second
    /// sliding window per caller id before a `ban_duration` ban.
    pub fn with_limits(threshold: u32, ban_duration: Duration, max_tracked: usize) -> Self {
        AttemptThrottle {
            limiter: RateLimiter::with_limits(threshold, ban_duration, max_tracked),
        }
    }

    /// Evaluate one attempt from `caller_id`. Returns `true` when the
    /// caller is allowed to proceed, `false` when they are over the
    /// limit or banned.
    ///
    /// `caller_id` must identify the calling peer (device id / IP),
    /// supplied by the adapter layer — not by the backend itself.
    pub fn check(&mut self, caller_id: &str) -> bool {
        self.limiter.handle_request(caller_id)
    }

    /// True when `caller_id` is currently banned (cleans up an expired ban).
    pub fn is_banned(&mut self, caller_id: &str) -> bool {
        self.limiter.is_banned(caller_id)
    }
}

impl Default for AttemptThrottle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_throttle() -> AttemptThrottle {
        AttemptThrottle::with_limits(3, Duration::from_secs(60), 100_000)
    }

    #[test]
    fn allowed_id_passes_repeatedly_under_limit() {
        let mut throttle = strict_throttle();
        for _ in 0..3 {
            assert!(throttle.check("device-1"));
        }
    }

    #[test]
    fn flooding_gets_denied() {
        let mut throttle = strict_throttle();
        assert!(throttle.check("device-1"));
        assert!(throttle.check("device-1"));
        assert!(throttle.check("device-1"));
        // Over the threshold: denied and banned.
        assert!(!throttle.check("device-1"));
        assert!(throttle.is_banned("device-1"));
        // Still denied while banned.
        assert!(!throttle.check("device-1"));
    }

    #[test]
    fn throttle_is_per_caller_id() {
        let mut throttle = strict_throttle();
        // Flood one caller id to its ban...
        for _ in 0..4 {
            throttle.check("device-1");
        }
        // ...and a different caller id is unaffected.
        assert!(throttle.check("device-2"));
        assert!(!throttle.check("device-1"));
    }

    #[test]
    fn default_throttle_builds() {
        let mut throttle = AttemptThrottle::new();
        assert!(throttle.check("some-device"));
    }
}
