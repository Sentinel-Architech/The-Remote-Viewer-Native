//! Progression and scoring.
//!
//! Score is "synapse points". Resolving anomalies raises Neural Integrity;
//! wrong answers are teaching moments (small reward, never punishment).
//! All math is saturating/checked — scores can never wrap or go negative.

use crate::zones::{Anomaly, Zone};

/// Points for linking a friendly neuron node.
pub const NEURON_LINK_POINTS: u32 = 10;
/// Base points per anomaly difficulty level on a correct answer.
pub const ANOMALY_BASE_POINTS: u32 = 50;
/// Consolation points for a wrong answer (teaching moment).
pub const WRONG_ANSWER_POINTS: u32 = 5;
/// Integrity gained per resolved anomaly (percentage points).
pub const INTEGRITY_PER_RESOLVE: u8 = 4;
/// Integrity lost per wrong answer (percentage points, floor at 0).
pub const INTEGRITY_PER_MISS: u8 = 1;
/// Bonus for mastering every zone in one dive.
pub const FULL_DIVE_BONUS: u32 = 250;

/// Tracks one dive's progression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    score: u32,
    integrity: u8, // 0..=100
    resolved: u32,
    attempted: u32,
    zones_mastered: Vec<Zone>,
}

impl Progress {
    /// Fresh dive: zero score, full integrity.
    pub fn new() -> Self {
        Progress {
            score: 0,
            integrity: 100,
            resolved: 0,
            attempted: 0,
            zones_mastered: Vec::new(),
        }
    }

    /// Current synapse-point score.
    pub fn score(&self) -> u32 {
        self.score
    }

    /// Neural Integrity, 0–100.
    pub fn integrity(&self) -> u8 {
        self.integrity
    }

    /// Anomalies resolved vs attempted.
    pub fn resolved(&self) -> u32 {
        self.resolved
    }
    /// Total challenges attempted.
    pub fn attempted(&self) -> u32 {
        self.attempted
    }

    /// Zones fully cleared this dive.
    pub fn zones_mastered(&self) -> &[Zone] {
        &self.zones_mastered
    }

    /// Link a friendly neuron: small score bump, no integrity change.
    pub fn link_neuron(&mut self) {
        self.score = self.score.saturating_add(NEURON_LINK_POINTS);
    }

    /// Resolve an anomaly challenge.
    ///
    /// `correct` awards difficulty-scaled points and restores integrity;
    /// a miss is a teaching moment: tiny points, small integrity dip
    /// (floored at zero — never negative).
    pub fn resolve_anomaly(&mut self, anomaly: Anomaly, correct: bool) {
        self.attempted = self.attempted.saturating_add(1);
        if correct {
            self.resolved = self.resolved.saturating_add(1);
            let pts = ANOMALY_BASE_POINTS.saturating_mul(anomaly.difficulty() as u32);
            self.score = self.score.saturating_add(pts);
            self.integrity = self.integrity.saturating_add(INTEGRITY_PER_RESOLVE).min(100);
        } else {
            self.score = self.score.saturating_add(WRONG_ANSWER_POINTS);
            self.integrity = self.integrity.saturating_sub(INTEGRITY_PER_MISS);
        }
    }

    /// Mark a zone mastered. Idempotent — mastering twice counts once.
    /// Awards the full-dive bonus when every zone is mastered.
    pub fn master_zone(&mut self, zone: Zone) {
        if !self.zones_mastered.contains(&zone) {
            self.zones_mastered.push(zone);
            if self.zones_mastered.len() == Zone::ALL.len() {
                self.score = self.score.saturating_add(FULL_DIVE_BONUS);
            }
        }
    }

    /// Accuracy 0–100 over attempted challenges. None attempted → 100
    /// (no failures yet), avoiding a divide-by-zero.
    pub fn accuracy(&self) -> u8 {
        if self.attempted == 0 {
            return 100;
        }
        ((self.resolved as u64 * 100) / self.attempted as u64).min(100) as u8
    }
}

impl Default for Progress {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_dive_state() {
        let p = Progress::new();
        assert_eq!(p.score(), 0);
        assert_eq!(p.integrity(), 100);
        assert_eq!(p.accuracy(), 100);
        assert!(p.zones_mastered().is_empty());
    }

    #[test]
    fn correct_answer_scales_with_difficulty() {
        let mut easy = Progress::new();
        easy.resolve_anomaly(Anomaly::FogBank, true); // difficulty 1
        let mut hard = Progress::new();
        hard.resolve_anomaly(Anomaly::CrimsonSurge, true); // difficulty 3
        assert_eq!(easy.score(), ANOMALY_BASE_POINTS);
        assert_eq!(hard.score(), ANOMALY_BASE_POINTS * 3);
        assert_eq!(easy.resolved(), 1);
        assert_eq!(easy.attempted(), 1);
    }

    #[test]
    fn wrong_answer_is_teaching_moment_not_punishment() {
        let mut p = Progress::new();
        p.resolve_anomaly(Anomaly::FogBank, false);
        assert_eq!(p.score(), WRONG_ANSWER_POINTS); // small, never zero-or-less
        assert_eq!(p.integrity(), 99); // dipped, not destroyed
        assert_eq!(p.resolved(), 0);
        assert_eq!(p.attempted(), 1);
        assert_eq!(p.accuracy(), 0);
    }

    #[test]
    fn integrity_floors_at_zero_and_caps_at_100() {
        let mut p = Progress::new();
        for _ in 0..200 {
            p.resolve_anomaly(Anomaly::FogBank, false);
        }
        assert_eq!(p.integrity(), 0); // floored, never underflows
        for _ in 0..200 {
            p.resolve_anomaly(Anomaly::FogBank, true);
        }
        assert_eq!(p.integrity(), 100); // capped, never overflows
    }

    #[test]
    fn score_saturates_never_wraps() {
        let mut p = Progress::new();
        p.score = u32::MAX - 1;
        p.resolve_anomaly(Anomaly::CrimsonSurge, true);
        assert_eq!(p.score(), u32::MAX);
    }

    #[test]
    fn neuron_link_adds_points() {
        let mut p = Progress::new();
        p.link_neuron();
        p.link_neuron();
        assert_eq!(p.score(), NEURON_LINK_POINTS * 2);
        assert_eq!(p.integrity(), 100); // untouched
    }

    #[test]
    fn mastering_all_zones_awards_bonus_once() {
        let mut p = Progress::new();
        for z in Zone::ALL {
            p.master_zone(z);
        }
        assert_eq!(p.score(), FULL_DIVE_BONUS);
        // Re-mastering changes nothing.
        p.master_zone(Zone::Cortex);
        assert_eq!(p.score(), FULL_DIVE_BONUS);
        assert_eq!(p.zones_mastered().len(), Zone::ALL.len());
    }

    #[test]
    fn accuracy_math() {
        let mut p = Progress::new();
        p.resolve_anomaly(Anomaly::FogBank, true);
        p.resolve_anomaly(Anomaly::FogBank, true);
        p.resolve_anomaly(Anomaly::FogBank, false);
        p.resolve_anomaly(Anomaly::FogBank, true);
        assert_eq!(p.accuracy(), 75); // 3/4
    }
}
