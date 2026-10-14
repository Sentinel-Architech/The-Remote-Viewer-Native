//! Scoring: the player earns points for containing threats quickly and
//! loses network integrity when threats deal damage.
//!
//! Win/lose: the mission ends when the clock runs out (see
//! [`crate::state::GameState::tick`]). Victory is graded, not binary:
//! the debrief reports a grade from S (flawless) to F (network lost).

/// Events that change the score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreEvent {
    /// Player contained a threat. Faster containment = more points.
    ThreatContained {
        /// Seconds the threat was active before containment.
        active_secs: u64,
        /// The response window for the mission's difficulty.
        response_window_secs: u64,
    },
    /// A threat dealt damage to the network.
    DamageTaken { amount: u32 },
    /// The player attempted to contain a non-active threat (misclick).
    FalsePositive,
}

/// Letter grade awarded at debrief.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grade {
    S,
    A,
    B,
    C,
    D,
    F,
}

impl core::fmt::Display for Grade {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Grade::S => "S",
            Grade::A => "A",
            Grade::B => "B",
            Grade::C => "C",
            Grade::D => "D",
            Grade::F => "F",
        };
        f.write_str(s)
    }
}

/// Running score for a mission.
#[derive(Debug, Clone)]
pub struct Score {
    points: i64,
    /// Network integrity: 100 = pristine, 0 = network lost.
    integrity: u32,
    threats_contained: u32,
    threats_escalated: u32,
    false_positives: u32,
}

impl Score {
    pub fn new() -> Self {
        Score {
            points: 0,
            integrity: 100,
            threats_contained: 0,
            threats_escalated: 0,
            false_positives: 0,
        }
    }

    pub fn points(&self) -> i64 {
        self.points
    }

    pub fn integrity(&self) -> u32 {
        self.integrity
    }

    pub fn threats_contained(&self) -> u32 {
        self.threats_contained
    }

    pub fn threats_escalated(&self) -> u32 {
        self.threats_escalated
    }

    /// True when the network has been lost (integrity hit zero).
    pub fn network_lost(&self) -> bool {
        self.integrity == 0
    }

    pub fn apply(&mut self, event: ScoreEvent) {
        match event {
            ScoreEvent::ThreatContained {
                active_secs,
                response_window_secs,
            } => {
                self.threats_contained = self.threats_contained.saturating_add(1);
                // Speed bonus: containing in the first quarter of the
                // window earns the most. Minimum 100 for any containment.
                let speed_ratio = if response_window_secs == 0 {
                    0
                } else {
                    active_secs.saturating_mul(100) / response_window_secs.max(1)
                };
                let bonus = 400u64.saturating_sub(speed_ratio.min(300) as u64 * 4 / 3);
                let award = 100i64.saturating_add(bonus.min(400) as i64);
                self.points = self.points.saturating_add(award);
            }
            ScoreEvent::DamageTaken { amount } => {
                self.integrity = self.integrity.saturating_sub(amount.min(100));
                self.points = self.points.saturating_sub(amount as i64 * 2);
                if self.integrity == 0 {
                    // Network lost is tracked via integrity; callers may
                    // also record escalations explicitly.
                }
            }
            ScoreEvent::FalsePositive => {
                self.false_positives = self.false_positives.saturating_add(1);
                self.points = self.points.saturating_sub(25);
            }
        }
    }

    /// Record that a threat escalated uncontained.
    pub fn record_escalation(&mut self) {
        self.threats_escalated = self.threats_escalated.saturating_add(1);
        self.points = self.points.saturating_sub(150);
    }

    /// Grant starting reputation carried over from Neural Mesh (part 1).
    /// Saturating — never wraps.
    pub fn grant_reputation(&mut self, points: u32) {
        self.points = self.points.saturating_add(points as i64);
    }

    /// Grade the mission at debrief.
    pub fn grade(&self) -> Grade {
        if self.network_lost() {
            return Grade::F;
        }
        let total = self.threats_contained + self.threats_escalated;
        let containment_rate = if total == 0 {
            100
        } else {
            self.threats_contained * 100 / total
        };
        match (containment_rate, self.integrity) {
            (100, 100) => Grade::S,
            (100, _) => Grade::A,
            (r, i) if r >= 75 && i >= 70 => Grade::B,
            (r, i) if r >= 50 && i >= 40 => Grade::C,
            (r, _) if r >= 25 => Grade::D,
            _ => Grade::F,
        }
    }
}

impl Default for Score {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_containment_earns_more() {
        let mut fast = Score::new();
        fast.apply(ScoreEvent::ThreatContained {
            active_secs: 2,
            response_window_secs: 40,
        });
        let mut slow = Score::new();
        slow.apply(ScoreEvent::ThreatContained {
            active_secs: 38,
            response_window_secs: 40,
        });
        assert!(fast.points() > slow.points());
        assert!(slow.points() >= 100); // minimum award
    }

    #[test]
    fn damage_reduces_integrity_and_points() {
        let mut s = Score::new();
        s.apply(ScoreEvent::DamageTaken { amount: 30 });
        assert_eq!(s.integrity(), 70);
        assert!(s.points() < 0);
    }

    #[test]
    fn integrity_cannot_go_below_zero() {
        let mut s = Score::new();
        s.apply(ScoreEvent::DamageTaken { amount: 500 });
        assert_eq!(s.integrity(), 0);
        assert!(s.network_lost());
        assert_eq!(s.grade(), Grade::F);
    }

    #[test]
    fn false_positive_costs_points() {
        let mut s = Score::new();
        s.apply(ScoreEvent::FalsePositive);
        assert_eq!(s.points(), -25);
    }

    #[test]
    fn flawless_mission_grades_s() {
        let mut s = Score::new();
        s.apply(ScoreEvent::ThreatContained {
            active_secs: 1,
            response_window_secs: 40,
        });
        assert_eq!(s.grade(), Grade::S);
    }

    #[test]
    fn sloppy_mission_grades_low() {
        let mut s = Score::new();
        s.apply(ScoreEvent::ThreatContained {
            active_secs: 1,
            response_window_secs: 40,
        });
        for _ in 0..3 {
            s.record_escalation();
        }
        // 25% containment -> D.
        assert_eq!(s.grade(), Grade::D);
    }

    #[test]
    fn grade_display() {
        assert_eq!(format!("{}", Grade::S), "S");
        assert_eq!(format!("{}", Grade::F), "F");
    }

    #[test]
    fn reputation_grant_saturates() {
        let mut s = Score::new();
        s.grant_reputation(1_500);
        assert_eq!(s.points(), 1_500);
        // Saturates at i64::MAX, never wraps.
        s.grant_reputation(u32::MAX);
        assert!(s.points() > 1_500);
        let mut maxed = Score::new();
        maxed.grant_reputation(u32::MAX);
        maxed.grant_reputation(u32::MAX);
        assert!(maxed.points() >= 0);
    }
}
