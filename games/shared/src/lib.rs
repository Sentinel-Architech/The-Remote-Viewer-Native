//! `trv-game-journey`: the single-journey contract between
//! **Neural Mesh (part 1)** and **God's Eye (part 2)**.
//!
//! Neural Mesh starts in the brain; as viruses and ailments are cured
//! (every neural zone healed), the Great Ascent transitions the player
//! into the decentralized globe of God's Eye. Part 2 is locked until
//! part 1 is complete.
//!
//! See [`transition`] for the trigger, the carried-over state, and the
//! save format. Std-only, zero dependencies.

pub mod transition;

pub use transition::{
    try_unlock, AnalystProfile, JourneyDifficulty, JourneyError, NeuralSummary,
    GREAT_ASCENT_DURATION_MS, GREAT_ASCENT_RINGS, JOURNEY_MAGIC, JOURNEY_VERSION, SAVE_LEN,
};
