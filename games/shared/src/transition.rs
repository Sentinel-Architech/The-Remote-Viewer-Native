//! The single-journey contract: **Neural Mesh (part 1)** → **God's Eye (part 2)**.
//!
//! # Narrative
//!
//! The player dives into the brain with the Sentinel (Neural Mesh), heals
//! every neural zone, and the **Great Ascent** carries them from the healed
//! mind outward into the decentralized globe of God's Eye. Part 2 is
//! **locked** until part 1 is complete: every zone mastered, nothing less.
//!
//! # Neutrality
//!
//! This crate knows nothing about either game's internal types. Each game
//! crate adapts its own types to/from the neutral [`NeuralSummary`] and
//! [`AnalystProfile`] via a small `journey` module:
//!
//! - `neural-mesh/src/journey.rs`: [`Progress`](https://example.invalid) → [`NeuralSummary`]
//! - `gods-eye/src/journey.rs`: [`AnalystProfile`] → difficulty + reputation
//!
//! # Save format (v1, 13 bytes, fixed length)
//!
//! ```text
//! [0..4]   magic "TRVJ"
//! [4]      version = 1
//! [5]      zones_mastered (u8)
//! [6]      zones_total (u8)
//! [7..11]  synapse_score (u32, little-endian)
//! [11]     integrity 0..=100 (u8)
//! [12]     accuracy  0..=100 (u8)
//! ```
//!
//! Decoding is fail-closed: bad magic, version, length, or out-of-range
//! fields all return [`JourneyError`] instead of a guess.
//!
//! Std-only, zero dependencies.

/// Magic bytes identifying a journey save.
pub const JOURNEY_MAGIC: [u8; 4] = *b"TRVJ";
/// Current save-format version.
pub const JOURNEY_VERSION: u8 = 1;
/// Fixed save length in bytes.
pub const SAVE_LEN: usize = 13;

/// The Great Ascent: cross-game vortex duration in milliseconds.
/// Longer than any single-game transition — the player is leaving one
/// world for another.
pub const GREAT_ASCENT_DURATION_MS: u64 = 3_000;
/// The Great Ascent: particle ring count.
pub const GREAT_ASCENT_RINGS: u32 = 30;

/// Completion snapshot of Neural Mesh (part 1).
///
/// Built by `neural-mesh` from its `Progress`; consumed here by
/// [`try_unlock`] and [`NeuralSummary::encode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeuralSummary {
    /// Neural zones fully healed.
    pub zones_mastered: u8,
    /// Total neural zones in the dive (5 in v1).
    pub zones_total: u8,
    /// Synapse points earned in part 1.
    pub synapse_score: u32,
    /// Neural Integrity at ascent, 0..=100.
    pub integrity: u8,
    /// Challenge accuracy at ascent, 0..=100.
    pub accuracy: u8,
}

/// Starting profile for God's Eye (part 2), derived from a completed part 1.
///
/// Only obtainable via [`try_unlock`], which enforces the trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalystProfile {
    /// Carried synapse points → starting reputation (bonus points).
    pub reputation: u32,
    /// 0..=100 analyst influence, from part-1 integrity and accuracy.
    pub influence: u8,
    /// Suggested starting difficulty for part 2.
    pub suggested_difficulty: JourneyDifficulty,
}

/// Difficulty suggestion carried across the journey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JourneyDifficulty {
    Cadet,
    Analyst,
    Sentinel,
}

/// Everything that can go wrong with the journey contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JourneyError {
    /// Part 1 is not complete: some neural zone is still unhealed.
    /// Part 2 stays locked.
    PartOneIncomplete,
    /// Save magic bytes are not `TRVJ`.
    BadMagic,
    /// Save version is not [`JOURNEY_VERSION`].
    BadVersion,
    /// Save is not exactly [`SAVE_LEN`] bytes.
    BadLength,
    /// A field is out of range (e.g. integrity > 100, or
    /// zones_mastered > zones_total). The save is corrupt.
    CorruptSave,
}

impl core::fmt::Display for JourneyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            JourneyError::PartOneIncomplete => "part 1 incomplete: heal every neural zone first",
            JourneyError::BadMagic => "journey save: bad magic",
            JourneyError::BadVersion => "journey save: unsupported version",
            JourneyError::BadLength => "journey save: bad length",
            JourneyError::CorruptSave => "journey save: corrupt fields",
        };
        f.write_str(s)
    }
}

impl std::error::Error for JourneyError {}

impl NeuralSummary {
    /// Encode into the fixed 13-byte save format.
    pub fn encode(&self) -> [u8; SAVE_LEN] {
        let mut out = [0u8; SAVE_LEN];
        out[0..4].copy_from_slice(&JOURNEY_MAGIC);
        out[4] = JOURNEY_VERSION;
        out[5] = self.zones_mastered;
        out[6] = self.zones_total;
        out[7..11].copy_from_slice(&self.synapse_score.to_le_bytes());
        out[11] = self.integrity;
        out[12] = self.accuracy;
        out
    }

    /// Decode a save, failing closed on anything unexpected.
    pub fn decode(bytes: &[u8]) -> Result<Self, JourneyError> {
        if bytes.len() != SAVE_LEN {
            return Err(JourneyError::BadLength);
        }
        if bytes[0..4] != JOURNEY_MAGIC {
            return Err(JourneyError::BadMagic);
        }
        if bytes[4] != JOURNEY_VERSION {
            return Err(JourneyError::BadVersion);
        }
        let zones_mastered = bytes[5];
        let zones_total = bytes[6];
        let synapse_score =
            u32::from_le_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]);
        let integrity = bytes[11];
        let accuracy = bytes[12];
        // Field validation: the save is corrupt if any field is
        // out of its legal range.
        if zones_total == 0
            || zones_mastered > zones_total
            || integrity > 100
            || accuracy > 100
        {
            return Err(JourneyError::CorruptSave);
        }
        Ok(NeuralSummary {
            zones_mastered,
            zones_total,
            synapse_score,
            integrity,
            accuracy,
        })
    }
}

/// The transition trigger: attempt to unlock part 2 from a part-1 summary.
///
/// Succeeds **only** when every neural zone is mastered
/// (`zones_mastered == zones_total`, with `zones_total > 0`).
/// Anything less returns [`JourneyError::PartOneIncomplete`] and part 2
/// stays locked.
///
/// The carried-over state:
/// - `synapse_score` → `reputation` (starting bonus points in part 2).
/// - `(integrity + accuracy) / 2` → `influence` 0..=100.
/// - `accuracy` → suggested difficulty: ≥90 Sentinel, ≥70 Analyst, else Cadet.
pub fn try_unlock(summary: &NeuralSummary) -> Result<AnalystProfile, JourneyError> {
    if summary.zones_total == 0 || summary.zones_mastered < summary.zones_total {
        return Err(JourneyError::PartOneIncomplete);
    }
    let influence = ((summary.integrity as u16 + summary.accuracy as u16) / 2).min(100) as u8;
    let suggested_difficulty = match summary.accuracy {
        90..=100 => JourneyDifficulty::Sentinel,
        70..=89 => JourneyDifficulty::Analyst,
        _ => JourneyDifficulty::Cadet,
    };
    Ok(AnalystProfile {
        reputation: summary.synapse_score,
        influence,
        suggested_difficulty,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_summary() -> NeuralSummary {
        NeuralSummary {
            zones_mastered: 5,
            zones_total: 5,
            synapse_score: 1_250,
            integrity: 96,
            accuracy: 92,
        }
    }

    #[test]
    fn complete_part_one_unlocks_part_two() {
        let profile = try_unlock(&complete_summary()).expect("complete dive unlocks");
        assert_eq!(profile.reputation, 1_250); // healing score carried over
        assert_eq!(profile.influence, 94); // (96 + 92) / 2
        assert_eq!(profile.suggested_difficulty, JourneyDifficulty::Sentinel);
    }

    #[test]
    fn difficulty_follows_accuracy_bands() {
        let mut s = complete_summary();
        s.accuracy = 95;
        assert_eq!(
            try_unlock(&s).unwrap().suggested_difficulty,
            JourneyDifficulty::Sentinel
        );
        s.accuracy = 89;
        assert_eq!(
            try_unlock(&s).unwrap().suggested_difficulty,
            JourneyDifficulty::Analyst
        );
        s.accuracy = 70;
        assert_eq!(
            try_unlock(&s).unwrap().suggested_difficulty,
            JourneyDifficulty::Analyst
        );
        s.accuracy = 69;
        assert_eq!(
            try_unlock(&s).unwrap().suggested_difficulty,
            JourneyDifficulty::Cadet
        );
        s.accuracy = 0;
        assert_eq!(
            try_unlock(&s).unwrap().suggested_difficulty,
            JourneyDifficulty::Cadet
        );
    }

    #[test]
    fn influence_is_average_of_integrity_and_accuracy() {
        let s = NeuralSummary {
            zones_mastered: 5,
            zones_total: 5,
            synapse_score: 0,
            integrity: 100,
            accuracy: 60,
        };
        assert_eq!(try_unlock(&s).unwrap().influence, 80);
    }

    #[test]
    fn partial_completion_stays_locked() {
        let mut s = complete_summary();
        s.zones_mastered = 4; // one zone still unhealed
        assert_eq!(try_unlock(&s), Err(JourneyError::PartOneIncomplete));
    }

    #[test]
    fn zero_progress_stays_locked() {
        let s = NeuralSummary {
            zones_mastered: 0,
            zones_total: 5,
            synapse_score: 0,
            integrity: 100,
            accuracy: 100,
        };
        assert_eq!(try_unlock(&s), Err(JourneyError::PartOneIncomplete));
    }

    #[test]
    fn empty_zones_total_stays_locked() {
        let s = NeuralSummary {
            zones_mastered: 0,
            zones_total: 0,
            synapse_score: 0,
            integrity: 100,
            accuracy: 100,
        };
        assert_eq!(try_unlock(&s), Err(JourneyError::PartOneIncomplete));
    }

    #[test]
    fn save_round_trips_exactly() {
        let s = complete_summary();
        let bytes = s.encode();
        assert_eq!(bytes.len(), SAVE_LEN);
        assert_eq!(&bytes[0..4], b"TRVJ");
        assert_eq!(bytes[4], JOURNEY_VERSION);
        assert_eq!(NeuralSummary::decode(&bytes), Ok(s));
    }

    #[test]
    fn save_rejects_bad_magic() {
        let mut bytes = complete_summary().encode();
        bytes[0] = b'X';
        assert_eq!(NeuralSummary::decode(&bytes), Err(JourneyError::BadMagic));
    }

    #[test]
    fn save_rejects_bad_version() {
        let mut bytes = complete_summary().encode();
        bytes[4] = 2;
        assert_eq!(NeuralSummary::decode(&bytes), Err(JourneyError::BadVersion));
    }

    #[test]
    fn save_rejects_bad_length() {
        let bytes = complete_summary().encode();
        assert_eq!(
            NeuralSummary::decode(&bytes[..SAVE_LEN - 1]),
            Err(JourneyError::BadLength)
        );
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(NeuralSummary::decode(&long), Err(JourneyError::BadLength));
        assert_eq!(NeuralSummary::decode(&[]), Err(JourneyError::BadLength));
    }

    #[test]
    fn save_rejects_corrupt_fields() {
        // integrity > 100
        let mut bytes = complete_summary().encode();
        bytes[11] = 101;
        assert_eq!(NeuralSummary::decode(&bytes), Err(JourneyError::CorruptSave));
        // accuracy > 100
        let mut bytes = complete_summary().encode();
        bytes[12] = 200;
        assert_eq!(NeuralSummary::decode(&bytes), Err(JourneyError::CorruptSave));
        // more zones mastered than exist
        let mut bytes = complete_summary().encode();
        bytes[5] = 6;
        assert_eq!(NeuralSummary::decode(&bytes), Err(JourneyError::CorruptSave));
        // zero zones total
        let mut bytes = complete_summary().encode();
        bytes[6] = 0;
        assert_eq!(NeuralSummary::decode(&bytes), Err(JourneyError::CorruptSave));
    }

    #[test]
    fn tampered_score_survives_as_data_but_needs_re_unlock() {
        // The save is data, not a trust root: anyone can edit the bytes,
        // but a forged "complete" save still had to pass decode, and the
        // platform layer re-validates unlock via try_unlock. A tampered
        // score decodes fine (it is just a number) — the trigger is what
        // gates part 2.
        let mut bytes = complete_summary().encode();
        bytes[7] = 0xFF;
        bytes[8] = 0xFF;
        let decoded = NeuralSummary::decode(&bytes).expect("score is just data");
        assert_ne!(decoded.synapse_score, complete_summary().synapse_score);
        // ...but the completion trigger still holds on the real fields.
        assert_eq!(decoded.zones_mastered, 5);
        assert!(try_unlock(&decoded).is_ok());
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(
            format!("{}", JourneyError::PartOneIncomplete),
            "part 1 incomplete: heal every neural zone first"
        );
        assert!(!format!("{}", JourneyError::CorruptSave).is_empty());
    }

    #[test]
    fn great_ascent_timing_constants_sane() {
        assert_eq!(GREAT_ASCENT_DURATION_MS, 3_000);
        assert_eq!(GREAT_ASCENT_RINGS, 30);
        // The cross-game transition is the longest vortex of all.
        assert!(GREAT_ASCENT_DURATION_MS > 2_400);
    }
}
