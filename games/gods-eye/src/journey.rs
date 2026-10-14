//! Part-2 side of the single-journey contract.
//!
//! God's Eye is the second half of one journey: it stays **locked** until
//! Neural Mesh (part 1) is complete — every neural zone healed. Given a
//! validated [`AnalystProfile`] from
//! [`try_unlock`](trv_game_journey::try_unlock), this module maps it onto
//! God's Eye types: a suggested starting difficulty and starting
//! reputation (bonus points).
//!
//! The platform layer flow:
//!
//! 1. Part 1 writes a journey save (`NeuralSummary::encode`).
//! 2. Part 2 reads it (`NeuralSummary::decode`), then
//!    `trv_game_journey::try_unlock(&summary)`.
//! 3. On `Ok(profile)`: [`difficulty_for`] picks the mission difficulty
//!    and [`apply_profile`] grants the reputation.
//! 4. On `Err(PartOneIncomplete)`: part 2 stays locked — show the player
//!    the way back to the Mesh.

use trv_game_journey::{AnalystProfile, JourneyDifficulty};

use crate::scoring::Score;
use crate::state::Difficulty;

/// Map the journey's suggested difficulty onto God's Eye difficulties.
pub fn difficulty_for(profile: &AnalystProfile) -> Difficulty {
    match profile.suggested_difficulty {
        JourneyDifficulty::Cadet => Difficulty::Cadet,
        JourneyDifficulty::Analyst => Difficulty::Analyst,
        JourneyDifficulty::Sentinel => Difficulty::Sentinel,
    }
}

/// Grant the carried reputation as starting bonus points on a fresh score.
pub fn apply_profile(score: &mut Score, profile: &AnalystProfile) {
    score.grant_reputation(profile.reputation);
}

/// The briefing line shown when part 2 unlocks after the Great Ascent.
pub fn journey_briefing(profile: &AnalystProfile) -> String {
    format!(
        "Analyst cleared by the Mesh. The healed mind now watches the globe. \
         Reputation: {}. Influence: {}.",
        profile.reputation, profile.influence
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use trv_game_journey::{try_unlock, NeuralSummary};

    fn unlocked_profile() -> AnalystProfile {
        let summary = NeuralSummary {
            zones_mastered: 5,
            zones_total: 5,
            synapse_score: 1_500,
            integrity: 90,
            accuracy: 75,
        };
        try_unlock(&summary).expect("complete dive unlocks")
    }

    #[test]
    fn difficulty_mapping_covers_all_bands() {
        let mut p = unlocked_profile();
        p.suggested_difficulty = JourneyDifficulty::Cadet;
        assert_eq!(difficulty_for(&p), Difficulty::Cadet);
        p.suggested_difficulty = JourneyDifficulty::Analyst;
        assert_eq!(difficulty_for(&p), Difficulty::Analyst);
        p.suggested_difficulty = JourneyDifficulty::Sentinel;
        assert_eq!(difficulty_for(&p), Difficulty::Sentinel);
    }

    #[test]
    fn accuracy_drives_starting_difficulty() {
        // 75% accuracy in part 1 → Analyst missions in part 2.
        assert_eq!(difficulty_for(&unlocked_profile()), Difficulty::Analyst);
    }

    #[test]
    fn reputation_becomes_starting_points() {
        let profile = unlocked_profile();
        let mut score = Score::new();
        assert_eq!(score.points(), 0);
        apply_profile(&mut score, &profile);
        assert_eq!(score.points(), 1_500); // healing score carried over
    }

    #[test]
    fn reputation_never_resets_mid_mission_progress() {
        let profile = unlocked_profile();
        let mut score = Score::new();
        apply_profile(&mut score, &profile);
        // Containment still adds on top of the carried reputation.
        score.apply(crate::scoring::ScoreEvent::ThreatContained {
            active_secs: 1,
            response_window_secs: 40,
        });
        assert!(score.points() > 1_500);
    }

    #[test]
    fn briefing_names_the_journey() {
        let b = journey_briefing(&unlocked_profile());
        assert!(b.contains("Mesh"));
        assert!(b.contains("1500"));
    }

    #[test]
    fn locked_journey_never_reaches_the_adapter() {
        // The adapter only ever sees validated profiles: try_unlock is
        // the gate, and it rejects incomplete dives before we get here.
        let summary = NeuralSummary {
            zones_mastered: 2,
            zones_total: 5,
            synapse_score: 300,
            integrity: 80,
            accuracy: 80,
        };
        assert!(try_unlock(&summary).is_err());
    }
}
