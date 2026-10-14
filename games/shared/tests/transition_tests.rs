//! End-to-end journey-contract tests: part 1 completes → part 2
//! unlocks with the correct carried state; anything less stays locked.

use trv_game_journey::{
    try_unlock, AnalystProfile, JourneyDifficulty, JourneyError, NeuralSummary,
};

fn full_dive() -> NeuralSummary {
    NeuralSummary {
        zones_mastered: 5,
        zones_total: 5,
        synapse_score: 2_000,
        integrity: 100,
        accuracy: 100,
    }
}

#[test]
fn perfect_dive_yields_max_profile() {
    let profile: AnalystProfile = try_unlock(&full_dive()).expect("unlocks");
    assert_eq!(profile.reputation, 2_000);
    assert_eq!(profile.influence, 100);
    assert_eq!(profile.suggested_difficulty, JourneyDifficulty::Sentinel);
}

#[test]
fn incomplete_dive_locks_part_two() {
    // 4 of 5 zones healed: the globe stays shut.
    let mut s = full_dive();
    s.zones_mastered = 4;
    assert_eq!(try_unlock(&s), Err(JourneyError::PartOneIncomplete));

    // Untouched dive: locked.
    let fresh = NeuralSummary {
        zones_mastered: 0,
        zones_total: 5,
        synapse_score: 0,
        integrity: 100,
        accuracy: 100,
    };
    assert_eq!(try_unlock(&fresh), Err(JourneyError::PartOneIncomplete));
}

#[test]
fn save_survives_the_trip_between_games() {
    // Part 1 writes the save; part 2 reads it back and unlocks.
    let written = full_dive().encode();
    let read_back = NeuralSummary::decode(&written).expect("part 2 reads the save");
    let profile = try_unlock(&read_back).expect("part 2 unlocks");
    assert_eq!(profile.reputation, 2_000);
}

#[test]
fn partial_save_cannot_unlock() {
    let mut s = full_dive();
    s.zones_mastered = 3;
    s.synapse_score = 900;
    let read_back = NeuralSummary::decode(&s.encode()).expect("decodes fine");
    assert_eq!(try_unlock(&read_back), Err(JourneyError::PartOneIncomplete));
}

#[test]
fn forged_completion_save_still_decodes_but_trigger_is_separate() {
    // A hand-edited save claiming 5/5 zones decodes (bytes are bytes);
    // the platform layer is expected to only ever write saves from real
    // gameplay. The trigger itself is pure: 5/5 unlocks, anything else
    // does not.
    let forged = NeuralSummary {
        zones_mastered: 5,
        zones_total: 5,
        synapse_score: 999_999,
        integrity: 100,
        accuracy: 100,
    };
    let read_back = NeuralSummary::decode(&forged.encode()).unwrap();
    assert!(try_unlock(&read_back).is_ok());
}

#[test]
fn error_messages_do_not_leak_save_bytes() {
    let msg = format!("{}", JourneyError::CorruptSave);
    assert!(!msg.contains("TRVJ"));
    assert!(!msg.is_empty());
}
