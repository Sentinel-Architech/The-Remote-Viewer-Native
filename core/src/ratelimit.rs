//! Sliding-window per-IP rate limiter with temporary bans.
//!
//! DDoS mitigation for edge nodes: request timestamps are tracked per IP in
//! a strict 1-second sliding window. An IP that exceeds the threshold is
//! banned for a fixed duration, and the ban is extended while the flood
//! continues. All state lives in local RAM; no network, no external
//! services, no corporate dependencies.
//!
//! Memory is bounded by design:
//! - expired bans and idle per-IP logs are swept periodically,
//! - a hard cap on tracked IPs sheds load instead of growing without limit
//!   under spoofed-source floods.
//! - a monotonic clock is used for all intervals, so wall-clock adjustments
//!   (NTP, manual changes) can never un-ban an attacker early.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Length of the sliding window: requests are counted per 1-second window.
const WINDOW: Duration = Duration::from_secs(1);
/// Minimum gap between stale-state sweeps (monotonic time).
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// A per-IP log idle this long is dropped by the sweep.
const IDLE_TTL: Duration = Duration::from_secs(60);

/// Sliding-window rate limiter with temporary per-IP bans.
///
/// Not thread-safe by itself; wrap in a `Mutex` if shared across threads.
#[derive(Debug)]
pub struct RateLimiter {
    /// Max requests per 1-second window before an IP is banned.
    threshold: u32,
    /// Base ban duration; extended while the flood continues.
    ban_duration: Duration,
    /// Hard cap on concurrently tracked IPs.
    max_tracked: usize,
    /// Per-IP sliding windows of request timestamps (monotonic).
    logs: HashMap<String, VecDeque<Instant>>,
    /// Active bans: IP -> ban expiry (monotonic).
    bans: HashMap<String, Instant>,
    /// Last time stale state was swept.
    last_sweep: Instant,
}

impl RateLimiter {
    /// Default limiter: 100 requests/second, 60-second bans, 100k tracked IPs.
    pub fn new() -> Self {
        Self::with_limits(100, Duration::from_secs(60), 100_000)
    }

    /// Limiter with explicit limits.
    pub fn with_limits(threshold: u32, ban_duration: Duration, max_tracked: usize) -> Self {
        RateLimiter {
            threshold,
            ban_duration,
            max_tracked,
            logs: HashMap::new(),
            bans: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }

    /// Evaluate one request from `ip`. Returns `true` if permitted.
    pub fn handle_request(&mut self, ip: &str) -> bool {
        self.handle_request_at(ip, Instant::now())
    }

    /// Evaluate one request from `ip` at monotonic time `now`.
    ///
    /// Exposed for deterministic testing; prefer [`handle_request`](#method.handle_request)
    /// in production.
    pub fn handle_request_at(&mut self, ip: &str, now: Instant) -> bool {
        self.sweep(now);

        // 1. Existing ban? Extend it while the flood continues.
        if let Some(&expiry) = self.bans.get(ip) {
            if now < expiry {
                self.bans.insert(ip.to_string(), now + self.ban_duration);
                return false;
            }
            self.bans.remove(ip);
        }

        // 2. Get or create the per-IP log, shedding load at the cap.
        let log = match self.logs.get_mut(ip) {
            Some(log) => log,
            None => {
                if self.logs.len() >= self.max_tracked {
                    return false;
                }
                self.logs.insert(ip.to_string(), VecDeque::new());
                // Inserted above; the key is present now.
                self.logs.get_mut(ip).expect("just inserted")
            }
        };

        // 3. Prune timestamps older than the 1-second window.
        while log.front().map_or(false, |&t| now.duration_since(t) > WINDOW) {
            log.pop_front();
        }

        // 4. Over threshold: ban and drop the log.
        if log.len() as u32 >= self.threshold {
            self.bans.insert(ip.to_string(), now + self.ban_duration);
            self.logs.remove(ip);
            return false;
        }

        // 5. Within budget: record and permit.
        log.push_back(now);
        true
    }

    /// Check whether `ip` is currently banned (cleans up an expired ban).
    pub fn is_banned(&mut self, ip: &str) -> bool {
        let now = Instant::now();
        match self.bans.get(ip) {
            Some(&expiry) if now < expiry => true,
            Some(_) => {
                self.bans.remove(ip);
                false
            }
            None => false,
        }
    }

    /// Number of IPs currently tracked (not banned).
    pub fn tracked_ips(&self) -> usize {
        self.logs.len()
    }

    /// Number of currently active bans.
    pub fn banned_count(&self) -> usize {
        self.bans.len()
    }

    /// Drop expired bans and idle per-IP logs. Runs at most every
    /// [`SWEEP_INTERVAL`], so the steady-state cost is negligible.
    fn sweep(&mut self, now: Instant) {
        if now.duration_since(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        self.bans.retain(|_, &mut expiry| now < expiry);
        self.logs
            .retain(|_, log| log.back().map_or(false, |&t| now.duration_since(t) <= IDLE_TTL));
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> RateLimiter {
        RateLimiter::with_limits(3, Duration::from_secs(60), 100_000)
    }

    /// Fire `n` requests from `ip` at the same instant; return the outcomes.
    fn burst(rl: &mut RateLimiter, ip: &str, n: u32, now: Instant) -> Vec<bool> {
        (0..n).map(|_| rl.handle_request_at(ip, now)).collect()
    }

    #[test]
    fn allows_requests_under_threshold() {
        let mut rl = limiter();
        let now = Instant::now();
        assert_eq!(burst(&mut rl, "10.0.0.1", 3, now), vec![true, true, true]);
    }

    #[test]
    fn bans_ip_over_threshold() {
        let mut rl = limiter();
        let now = Instant::now();
        assert_eq!(burst(&mut rl, "10.0.0.1", 4, now), vec![true, true, true, false]);
        assert!(rl.is_banned("10.0.0.1"));
        assert_eq!(rl.banned_count(), 1);
    }

    #[test]
    fn ban_blocks_further_requests_and_extends() {
        let mut rl = limiter();
        let t0 = Instant::now();
        burst(&mut rl, "10.0.0.1", 4, t0); // triggers ban, expiry = t0 + 60s
        // Still banned 30s later; the attempt extends the ban to t0 + 90s.
        assert!(!rl.handle_request_at("10.0.0.1", t0 + Duration::from_secs(30)));
        // The extension holds past the original expiry, and this attempt
        // extends it again to t0 + 121s.
        assert!(!rl.handle_request_at("10.0.0.1", t0 + Duration::from_secs(61)));
        // Once the flood stops, the ban finally lapses.
        assert!(rl.handle_request_at("10.0.0.1", t0 + Duration::from_secs(122)));
    }

    #[test]
    fn ban_expires_without_further_traffic() {
        let mut rl = limiter();
        let t0 = Instant::now();
        burst(&mut rl, "10.0.0.1", 4, t0);
        assert!(rl.handle_request_at("10.0.0.1", t0 + Duration::from_secs(61)));
        assert!(!rl.is_banned("10.0.0.1"));
    }

    #[test]
    fn window_slides_so_old_requests_stop_counting() {
        let mut rl = limiter();
        let t0 = Instant::now();
        burst(&mut rl, "10.0.0.1", 3, t0);
        // 1.5s later the old timestamps fall out of the 1-second window.
        let later = t0 + Duration::from_millis(1500);
        assert_eq!(burst(&mut rl, "10.0.0.1", 3, later), vec![true, true, true]);
    }

    #[test]
    fn per_ip_isolation() {
        let mut rl = limiter();
        let now = Instant::now();
        burst(&mut rl, "10.0.0.1", 4, now); // banned
        // A different IP is unaffected.
        assert_eq!(burst(&mut rl, "10.0.0.2", 3, now), vec![true, true, true]);
    }

    #[test]
    fn sweep_drops_idle_logs_but_keeps_active_ones() {
        let mut rl = limiter();
        let t0 = Instant::now();
        rl.handle_request_at("10.0.0.1", t0);
        rl.handle_request_at("10.0.0.2", t0);
        assert_eq!(rl.tracked_ips(), 2);
        // 61s later only .2 sends again: sweep drops idle .1, keeps .2.
        let later = t0 + Duration::from_secs(61);
        assert!(rl.handle_request_at("10.0.0.2", later));
        assert_eq!(rl.tracked_ips(), 1);
    }

    #[test]
    fn max_tracked_sheds_load_instead_of_growing() {
        let mut rl = RateLimiter::with_limits(1000, Duration::from_secs(60), 2);
        let now = Instant::now();
        assert!(rl.handle_request_at("10.0.0.1", now));
        assert!(rl.handle_request_at("10.0.0.2", now));
        // At the cap: a brand-new IP is shed, tracked IPs are not.
        assert!(!rl.handle_request_at("10.0.0.3", now));
        assert!(rl.handle_request_at("10.0.0.1", now));
        assert_eq!(rl.tracked_ips(), 2);
    }

    #[test]
    fn default_limits_are_sane() {
        let rl = RateLimiter::new();
        assert_eq!(rl.threshold, 100);
        assert_eq!(rl.ban_duration, Duration::from_secs(60));
        assert_eq!(rl.max_tracked, 100_000);
    }
}
