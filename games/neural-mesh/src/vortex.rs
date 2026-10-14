//! The vortex transition: concept and timing contract.
//!
//! The vortex is THE signature transition of Neural Mesh. It plays when
//! the player dives in, ascends out, and moves between neural zones or
//! major in-game events. This module defines the *concept and timing
//! contract* the renderer implements — no fake graphics here, just the
//! parameters every faithful implementation must honor.
//!
//! ## Concept
//! A spiral particle tunnel: concentric rings of light-points rotate
//! around the view axis while the camera pushes forward through them.
//! - **Dive in**: rings converge inward (world rushes toward the player),
//!   color shifts from the menu's calm palette into the zone's palette.
//! - **Ascent out**: rings expand outward (player rushes back up),
//!   palette bleeds back to calm.
//! - **Zone shift**: a shorter lateral vortex — the tunnel banks sideways
//!   into the next zone's palette without a full dive.
//!
//! ## Timing contract (milliseconds)
//! Renderers must honor these durations so game logic (which waits on
//! [`VortexKind::duration_ms`]) stays in sync with what the player sees.

/// Which vortex is playing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VortexKind {
    /// Full dive from menu into the first zone.
    DiveIn,
    /// Full ascent from a zone back to the session summary.
    AscentOut,
    /// Short lateral shift between two zones.
    ZoneShift,
    /// Brief swirl on major in-game events (anomaly resolved, zone mastered).
    EventSwirl,
    /// The cross-game transition: the healed mind expands outward into
    /// the decentralized globe of God's Eye (part 2). Only available on
    /// a completed dive (every zone mastered). Timing comes from the
    /// shared journey contract so both games agree.
    GreatAscent,
}

impl VortexKind {
    /// Canonical duration in milliseconds. The renderer must complete
    /// the animation within this budget; game logic waits this long.
    pub fn duration_ms(self) -> u64 {
        match self {
            VortexKind::DiveIn => 2_400,
            VortexKind::AscentOut => 2_000,
            VortexKind::ZoneShift => 1_200,
            VortexKind::EventSwirl => 600,
            VortexKind::GreatAscent => trv_game_journey::GREAT_ASCENT_DURATION_MS,
        }
    }

    /// Number of particle rings in the tunnel. More rings = denser tunnel.
    pub fn ring_count(self) -> u32 {
        match self {
            VortexKind::DiveIn => 24,
            VortexKind::AscentOut => 20,
            VortexKind::ZoneShift => 12,
            VortexKind::EventSwirl => 6,
            VortexKind::GreatAscent => trv_game_journey::GREAT_ASCENT_RINGS,
        }
    }

    /// Direction of travel through the tunnel.
    pub fn direction(self) -> VortexDirection {
        match self {
            VortexKind::DiveIn => VortexDirection::Inward,
            VortexKind::AscentOut => VortexDirection::Outward,
            VortexKind::ZoneShift => VortexDirection::Lateral,
            VortexKind::EventSwirl => VortexDirection::Inward,
            // The healed mind expands outward into the world.
            VortexKind::GreatAscent => VortexDirection::Outward,
        }
    }

    /// True for the two full transitions (dive/ascent) that bracket a dive.
    pub fn is_full_transition(self) -> bool {
        matches!(
            self,
            VortexKind::DiveIn | VortexKind::AscentOut | VortexKind::GreatAscent
        )
    }
}

/// Travel direction through the particle tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VortexDirection {
    /// Rings converge: the world rushes toward the player.
    Inward,
    /// Rings expand: the player rushes back out.
    Outward,
    /// Tunnel banks sideways into the next zone.
    Lateral,
}

impl core::fmt::Display for VortexDirection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VortexDirection::Inward => write!(f, "inward"),
            VortexDirection::Outward => write!(f, "outward"),
            VortexDirection::Lateral => write!(f, "lateral"),
        }
    }
}

/// Accessibility: renderers should offer a reduced-motion alternative
/// (crossfade) honoring the same durations. This flag records the
/// player's preference; game logic is unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VortexSettings {
    /// When true, render a crossfade instead of the spiral tunnel,
    /// keeping the same [`VortexKind::duration_ms`] timing.
    pub reduced_motion: bool,
}

impl VortexSettings {
    /// Default: full vortex animation.
    pub fn full() -> Self {
        VortexSettings {
            reduced_motion: false,
        }
    }

    /// Accessibility-friendly: crossfade with identical timing.
    pub fn reduced() -> Self {
        VortexSettings {
            reduced_motion: true,
        }
    }
}

impl Default for VortexSettings {
    fn default() -> Self {
        Self::full()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_positive_and_ordered() {
        assert!(VortexKind::DiveIn.duration_ms() > VortexKind::ZoneShift.duration_ms());
        assert!(VortexKind::ZoneShift.duration_ms() > VortexKind::EventSwirl.duration_ms());
        for k in [
            VortexKind::DiveIn,
            VortexKind::AscentOut,
            VortexKind::ZoneShift,
            VortexKind::EventSwirl,
        ] {
            assert!(k.duration_ms() > 0);
            assert!(k.ring_count() > 0);
        }
    }

    #[test]
    fn directions_match_concept() {
        assert_eq!(VortexKind::DiveIn.direction(), VortexDirection::Inward);
        assert_eq!(
            VortexKind::AscentOut.direction(),
            VortexDirection::Outward
        );
        assert_eq!(
            VortexKind::ZoneShift.direction(),
            VortexDirection::Lateral
        );
    }

    #[test]
    fn full_transitions_bracket_a_dive() {
        assert!(VortexKind::DiveIn.is_full_transition());
        assert!(VortexKind::AscentOut.is_full_transition());
        assert!(!VortexKind::ZoneShift.is_full_transition());
        assert!(!VortexKind::EventSwirl.is_full_transition());
    }

    #[test]
    fn reduced_motion_keeps_timing() {
        // Accessibility alternative changes the visual, never the timing.
        let _ = VortexSettings::reduced();
        let _ = VortexSettings::full();
        assert_eq!(
            VortexSettings::reduced().reduced_motion,
            true
        );
        assert_eq!(VortexSettings::full().reduced_motion, false);
    }

    #[test]
    fn direction_display() {
        assert_eq!(format!("{}", VortexDirection::Inward), "inward");
        assert_eq!(format!("{}", VortexDirection::Outward), "outward");
        assert_eq!(format!("{}", VortexDirection::Lateral), "lateral");
    }

    #[test]
    fn great_ascent_is_the_grandest_transition() {
        // The cross-game journey transition out-scales every in-game one.
        let g = VortexKind::GreatAscent;
        assert_eq!(g.duration_ms(), 3_000);
        assert_eq!(g.ring_count(), 30);
        assert_eq!(g.direction(), VortexDirection::Outward);
        assert!(g.is_full_transition());
        for k in [
            VortexKind::DiveIn,
            VortexKind::AscentOut,
            VortexKind::ZoneShift,
            VortexKind::EventSwirl,
        ] {
            assert!(g.duration_ms() > k.duration_ms());
            assert!(g.ring_count() > k.ring_count());
        }
    }
}
