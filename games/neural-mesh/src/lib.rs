//! Neural Mesh (code name `neural-link`).
//!
//! One of the only TWO simulation games in the TRV DApp. A matrix-themed
//! journey through the brain: the player dives with the Sentinel into a
//! stylized neural landscape, explores brain zones, resolves anomalies
//! through educational challenges, and ascends.
//!
//! # Educational entertainment — not medical advice
//!
//! Everything in this game is creative direction for entertainment and
//! general brain-health *awareness*. It is NOT medical advice, diagnosis,
//! or treatment. Nothing here should be used to assess, prevent, or treat
//! any medical condition. Consult a qualified professional for anything
//! health-related. See [`MEDICAL_DISCLAIMER`].
//!
//! This crate is a **logic scaffold**: game state machine, zones,
//! entities, progression, and the vortex-transition concept. Rendering,
//! audio, and input are provided by the platform layer (see README.md).

/// Prominent in-game disclaimer. Display it on first launch and in the
/// game's about screen. Never remove or shorten it.
pub const MEDICAL_DISCLAIMER: &str = "Neural Mesh is educational entertainment, \
not medical advice. It does not diagnose, treat, or prevent any condition. \
For health concerns, consult a qualified medical professional.";

/// Crate version, mirrored from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod journey;
pub mod progression;
pub mod state;
pub mod vortex;
pub mod zones;
