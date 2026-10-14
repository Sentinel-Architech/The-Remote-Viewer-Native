//! Part-1 side of the single-journey contract.
//!
//! When every neural zone is mastered, the dive is complete and the
//! player may take the **Great Ascent** into God's Eye (part 2).
//! This module adapts [`Progress`] to the neutral [`NeuralSummary`]
//! defined in `trv-game-journey`; the trigger itself
//! ([`try_unlock`](trv_game_journey::try_unlock)) lives there.

use trv_game_journey::NeuralSummary;

use crate::progression::Progress;
use crate::zones::Zone;

/// Build the journey summary from the current dive progress.
pub fn summarize(progress: &Progress) -> NeuralSummary {
    NeuralSummary {
        zones_mastered: progress.zones_mastered().len().min(255) as u8,
        zones_total: Zone::ALL.len().min(255) as u8,
        synapse_score: progress.score(),
        integrity: progress.integrity(),
        accuracy: progress.accuracy(),
    }
}

/// True when the dive is complete: every neural zone mastered.
/// Only a completed dive can take the Great Ascent.
pub fn journey_complete(progress: &Progress) -> bool {
    let mastered = progress.zones_mastered();
    Zone::ALL.iter().all(|z| mastered.contains(z))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zones::Anomaly;
    use trv_game_journey::{try_unlock, JourneyDifficulty};

    fn completed_dive() -> Progress {
        let mut p = Progress::new();
        // Heal every zone (one anomaly each is enough for the trigger;
        // real gameplay heals them all).
        for &z in &Zone::ALL {
            p.master_zone(z);
        }
        p.resolve_anomaly(Anomaly::FogBank, true);
        p
    }

    #[test]
    fn full_dive_summarizes_and_unlocks() {
        let p = completed_dive();
        assert!(journey_complete(&p));
        let summary = summarize(&p);
        assert_eq!(summary.zones_mastered, 5);
        assert_eq!(summary.zones_total, 5);
        let profile = try_unlock(&summary).expect("part 2 unlocks");
        // Healing score carried over as reputation.
        assert_eq!(profile.reputation, p.score());
        assert_eq!(profile.suggested_difficulty, JourneyDifficulty::Sentinel);
    }

    #[test]
    fn partial_dive_summarizes_but_stays_locked() {
        let mut p = Progress::new();
        for &z in &Zone::ALL[..4] {
            p.master_zone(z);
        }
        assert!(!journey_complete(&p));
        let summary = summarize(&p);
        assert_eq!(summary.zones_mastered, 4);
        assert_eq!(
            try_unlock(&summary),
            Err(trv_game_journey::JourneyError::PartOneIncomplete)
        );
    }

    #[test]
    fn fresh_dive_is_not_complete() {
        let p = Progress::new();
        assert!(!journey_complete(&p));
        let summary = summarize(&p);
        assert_eq!(summary.zones_mastered, 0);
        assert_eq!(summary.synapse_score, 0);
    }

    #[test]
    fn re_mastering_does_not_inflate_the_summary() {
        let mut p = completed_dive();
        p.master_zone(Zone::Cortex); // already mastered: idempotent
        let summary = summarize(&p);
        assert_eq!(summary.zones_mastered, 5); // never exceeds the zone count
    }
}
