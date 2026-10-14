//! The vortex transition: how the player moves in and out of God's Eye.
//!
//! Per the product spec, transitions into/out of games (and between
//! in-game events) use a vortex animation. This module defines the
//! transition as DATA — direction, duration, intensity — so the
//! platform rendering layer (which owns the GPU) can realize it
//! faithfully on any device. No fake graphics in this crate.
//!
//! Design concept (for the renderer):
//! - A spiral tunnel that appears to pull the player's view inward
//!   (entering) or push it outward (exiting).
//! - Color language: deep green matrix tones, matching the Sentinel's
//!   aura — the game is entered through the Sentinel's eye.
//! - Duration scales with intensity: quick hops between events use a
//!   short swirl; full enter/exit use the deep dive.
//! - The transition must never block input longer than its duration,
//!   and must be skippable on low-power devices (accessibility).

/// Direction of the vortex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VortexDirection {
    /// Into the game (or into an event): spiral inward.
    Enter,
    /// Out of the game (or event): spiral outward.
    Exit,
}

/// How deep the transition goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VortexDepth {
    /// Quick hop between in-game events (~0.6s).
    Shallow,
    /// Full enter/exit of the game (~1.8s).
    Deep,
}

impl VortexDepth {
    /// Nominal duration in milliseconds for the renderer.
    pub fn duration_ms(self) -> u64 {
        match self {
            VortexDepth::Shallow => 600,
            VortexDepth::Deep => 1800,
        }
    }
}

/// A single vortex transition request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VortexTransition {
    pub direction: VortexDirection,
    pub depth: VortexDepth,
    /// If true, the renderer may substitute a simple fade
    /// (low-power devices, motion-sensitivity accessibility).
    pub allow_reduced_motion: bool,
}

impl VortexTransition {
    pub fn enter_game() -> Self {
        VortexTransition {
            direction: VortexDirection::Enter,
            depth: VortexDepth::Deep,
            allow_reduced_motion: true,
        }
    }

    pub fn exit_game() -> Self {
        VortexTransition {
            direction: VortexDirection::Exit,
            depth: VortexDepth::Deep,
            allow_reduced_motion: true,
        }
    }

    pub fn between_events() -> Self {
        VortexTransition {
            direction: VortexDirection::Enter,
            depth: VortexDepth::Shallow,
            allow_reduced_motion: true,
        }
    }

    pub fn duration_ms(&self) -> u64 {
        self.depth.duration_ms()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_durations_sane() {
        assert!(VortexTransition::between_events().duration_ms()
            < VortexTransition::enter_game().duration_ms());
        assert_eq!(VortexTransition::enter_game().duration_ms(), 1800);
        assert_eq!(VortexTransition::between_events().duration_ms(), 600);
    }

    #[test]
    fn enter_and_exit_are_opposites() {
        let enter = VortexTransition::enter_game();
        let exit = VortexTransition::exit_game();
        assert_eq!(enter.direction, VortexDirection::Enter);
        assert_eq!(exit.direction, VortexDirection::Exit);
        assert_eq!(enter.depth, exit.depth);
    }

    #[test]
    fn reduced_motion_always_allowed() {
        // Accessibility is non-negotiable.
        assert!(VortexTransition::enter_game().allow_reduced_motion);
        assert!(VortexTransition::exit_game().allow_reduced_motion);
        assert!(VortexTransition::between_events().allow_reduced_motion);
    }
}
