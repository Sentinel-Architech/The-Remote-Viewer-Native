//! Neural zones and entities.
//!
//! Zones are stylized brain regions rendered as matrix landscapes.
//! Anomalies are gameplay encounters themed around brain-health
//! *awareness* topics. They teach general knowledge (e.g. "sleep matters
//! for memory") — never diagnosis, never treatment. See the crate-level
//! disclaimer.

/// The explorable brain zones, in canonical dive order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Zone {
    /// Outer thought-fields: logic puzzles, pattern recognition.
    Cortex,
    /// Memory vaults: recall and association challenges.
    Hippocampus,
    /// Emotional weather: stress-awareness scenarios.
    Limbic,
    /// Rhythm core: breathing and focus exercises.
    Brainstem,
    /// Motion lattice: coordination and reaction trials.
    Cerebellum,
}

impl Zone {
    /// All zones in dive order.
    pub const ALL: [Zone; 5] = [
        Zone::Cortex,
        Zone::Hippocampus,
        Zone::Limbic,
        Zone::Brainstem,
        Zone::Cerebellum,
    ];

    /// Display name for UI.
    pub fn name(self) -> &'static str {
        match self {
            Zone::Cortex => "Cortex Fields",
            Zone::Hippocampus => "Hippocampus Vaults",
            Zone::Limbic => "Limbic Weather",
            Zone::Brainstem => "Brainstem Core",
            Zone::Cerebellum => "Cerebellum Lattice",
        }
    }

    /// One-line flavor text. Educational-awareness tone, no medical claims.
    pub fn flavor(self) -> &'static str {
        match self {
            Zone::Cortex => "Where thoughts take shape. Keep the fields clear.",
            Zone::Hippocampus => "Every memory is a vault. Visit them often.",
            Zone::Limbic => "Storms pass. Learning to weather them is a skill.",
            Zone::Brainstem => "The oldest rhythm. Breath in, breath out.",
            Zone::Cerebellum => "Balance is practice, not talent.",
        }
    }

    /// Zone after this one in dive order, if any.
    pub fn next(self) -> Option<Zone> {
        let i = Self::ALL.iter().position(|&z| z == self)?;
        Self::ALL.get(i + 1).copied()
    }
}

/// Friendly entities that aid the player.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ally {
    /// The Sentinel itself, guiding the dive.
    SentinelGuide,
    /// A healthy neuron node; grants small score when linked.
    Neuron,
    /// A glial helper; clears minor static.
    Glial,
}

/// Anomalies: gameplay encounters themed around brain-health awareness.
/// Names are metaphorical; each carries an educational topic tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Anomaly {
    /// Topic: sleep supports memory (awareness only).
    FogBank,
    /// Topic: chronic stress awareness; coping strategies exist.
    StaticStorm,
    /// Topic: hydration and focus (general wellness awareness).
    DryStatic,
    /// Topic: learning/memory thrives on repetition and rest.
    FadingEcho,
    /// Topic: know stroke warning signs (FAST) — seek help fast.
    /// Presented as public-awareness information, not diagnosis.
    CrimsonSurge,
    /// Topic: concussion awareness — protect your head, rest after injury.
    FractureLine,
}

impl Anomaly {
    /// All anomalies.
    pub const ALL: [Anomaly; 6] = [
        Anomaly::FogBank,
        Anomaly::StaticStorm,
        Anomaly::DryStatic,
        Anomaly::FadingEcho,
        Anomaly::CrimsonSurge,
        Anomaly::FractureLine,
    ];

    /// Display name for UI.
    pub fn name(self) -> &'static str {
        match self {
            Anomaly::FogBank => "Fog Bank",
            Anomaly::StaticStorm => "Static Storm",
            Anomaly::DryStatic => "Dry Static",
            Anomaly::FadingEcho => "Fading Echo",
            Anomaly::CrimsonSurge => "Crimson Surge",
            Anomaly::FractureLine => "Fracture Line",
        }
    }

    /// The awareness topic this anomaly teaches. General information
    /// only — never medical advice.
    pub fn topic(self) -> &'static str {
        match self {
            Anomaly::FogBank => "Sleep supports memory consolidation.",
            Anomaly::StaticStorm => "Chronic stress affects focus; coping strategies help.",
            Anomaly::DryStatic => "Hydration supports everyday alertness.",
            Anomaly::FadingEcho => "Repetition and rest strengthen learning.",
            Anomaly::CrimsonSurge => {
                "Know stroke warning signs (FAST: Face, Arms, Speech, Time). \
                 In a real emergency, call emergency services immediately."
            }
            Anomaly::FractureLine => {
                "Head injuries deserve rest and professional evaluation. \
                 When in doubt, get checked."
            }
        }
    }

    /// Which zones this anomaly can appear in.
    pub fn zones(self) -> &'static [Zone] {
        match self {
            Anomaly::FogBank => &[Zone::Hippocampus, Zone::Cortex],
            Anomaly::StaticStorm => &[Zone::Limbic, Zone::Cortex],
            Anomaly::DryStatic => &[Zone::Brainstem, Zone::Cerebellum],
            Anomaly::FadingEcho => &[Zone::Hippocampus],
            Anomaly::CrimsonSurge => &[Zone::Brainstem, Zone::Cortex],
            Anomaly::FractureLine => &[Zone::Cerebellum, Zone::Cortex],
        }
    }

    /// Difficulty weight 1–3 for scoring.
    pub fn difficulty(self) -> u8 {
        match self {
            Anomaly::FogBank => 1,
            Anomaly::DryStatic => 1,
            Anomaly::FadingEcho => 2,
            Anomaly::StaticStorm => 2,
            Anomaly::FractureLine => 3,
            Anomaly::CrimsonSurge => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zones_form_a_chain() {
        let mut z = Zone::Cortex;
        let mut seen = 1;
        while let Some(n) = z.next() {
            z = n;
            seen += 1;
        }
        assert_eq!(seen, Zone::ALL.len());
        assert_eq!(z, Zone::Cerebellum);
    }

    #[test]
    fn every_zone_has_flavor_and_name() {
        for z in Zone::ALL {
            assert!(!z.name().is_empty());
            assert!(!z.flavor().is_empty());
        }
    }

    #[test]
    fn every_anomaly_has_topic_and_zones() {
        for a in Anomaly::ALL {
            assert!(!a.name().is_empty());
            assert!(!a.topic().is_empty());
            assert!(!a.zones().is_empty());
            assert!((1..=3).contains(&a.difficulty()));
        }
    }

    #[test]
    fn anomaly_zones_are_valid() {
        for a in Anomaly::ALL {
            for z in a.zones() {
                assert!(Zone::ALL.contains(z));
            }
        }
    }

    #[test]
    fn emergency_topics_direct_to_professionals() {
        // The two urgent-awareness anomalies must point at real help,
        // never at self-management.
        let surge = Anomaly::CrimsonSurge.topic();
        assert!(surge.contains("emergency services"));
        let fracture = Anomaly::FractureLine.topic();
        assert!(fracture.contains("professional"));
    }
}
