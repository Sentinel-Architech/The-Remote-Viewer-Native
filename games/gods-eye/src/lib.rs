//! God's Eye — cyber-threat simulation game for The Remote Viewer Network.
//!
//! One of only TWO simulation games in the DApp. Educational for the
//! Sentinel: every mission teaches real threat-awareness concepts
//! (phishing, intrusion, supply-chain attacks, social engineering)
//! while the player defends a simulated network as a homeland-security
//! style analyst.
//!
//! This crate is the pure game LOGIC: state machine, threat entities,
//! and scoring. Rendering (high-resolution immersive visuals) and the
//! vortex transition animation live in the platform layer; the design
//! doc in README.md describes them. No fake graphics here.
//!
//! std-only, zero dependencies.

pub mod state;
pub mod threats;
pub mod scoring;
pub mod vortex;
pub mod journey;

pub use state::{GameState, Phase, Mission, MissionConfig};
pub use threats::{Threat, ThreatKind, ThreatId, ThreatBehavior};
pub use scoring::{Score, ScoreEvent};
pub use vortex::VortexTransition;
