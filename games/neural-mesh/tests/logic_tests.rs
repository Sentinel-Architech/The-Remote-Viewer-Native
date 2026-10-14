//! End-to-end logic tests: a full scripted dive.

use trv_neural_mesh::progression::Progress;
use trv_neural_mesh::state::{Event, Game, Phase};
use trv_neural_mesh::vortex::{VortexKind, VortexSettings};
use trv_neural_mesh::zones::{Anomaly, Zone};
use trv_neural_mesh::{MEDICAL_DISCLAIMER, VERSION};

#[test]
fn disclaimer_is_present_and_unshortened() {
    assert!(MEDICAL_DISCLAIMER.contains("not medical advice"));
    assert!(MEDICAL_DISCLAIMER.contains("educational entertainment"));
    assert!(MEDICAL_DISCLAIMER.contains("qualified medical professional"));
    assert!(MEDICAL_DISCLAIMER.len() > 100);
}

#[test]
fn version_is_set() {
    assert!(!VERSION.is_empty());
}

#[test]
fn scripted_full_dive_with_scoring() {
    let mut game = Game::new();
    let mut progress = Progress::new();

    // Disclaimer acknowledged, dive in.
    game.apply(Event::Start).unwrap();
    assert_eq!(game.phase(), Phase::Dive);
    assert_eq!(VortexKind::DiveIn.duration_ms(), 2_400);

    // Arrive in the Cortex.
    game.apply(Event::DiveComplete).unwrap();
    assert_eq!(game.phase(), Phase::Zone);

    // Link a neuron, then hit a Fog Bank and answer correctly.
    progress.link_neuron();
    game.apply(Event::AnomalyEncountered).unwrap();
    assert_eq!(game.phase(), Phase::Challenge);
    progress.resolve_anomaly(Anomaly::FogBank, true);
    game.apply(Event::ChallengeAnswered { correct: true }).unwrap();
    assert_eq!(game.phase(), Phase::Resolution);
    game.apply(Event::ResolutionComplete).unwrap();
    assert_eq!(game.phase(), Phase::Zone);

    // Score: 10 (neuron) + 50 (difficulty-1 anomaly, correct).
    assert_eq!(progress.score(), 60);
    assert_eq!(progress.integrity(), 100); // capped, was already full
    assert_eq!(progress.accuracy(), 100);

    // Master the Cortex, shift vortex to the next zone.
    progress.master_zone(Zone::Cortex);
    assert_eq!(VortexKind::ZoneShift.duration_ms(), 1_200);

    // A harder anomaly, answered wrong: teaching moment.
    game.apply(Event::AnomalyEncountered).unwrap();
    progress.resolve_anomaly(Anomaly::StaticStorm, false);
    game.apply(Event::ChallengeAnswered { correct: false }).unwrap();
    game.apply(Event::ResolutionComplete).unwrap();
    assert_eq!(progress.score(), 65); // +5 consolation
    assert_eq!(progress.integrity(), 99);
    assert_eq!(progress.accuracy(), 50);

    // Finish: ascend out.
    game.apply(Event::Ascend).unwrap();
    assert_eq!(game.phase(), Phase::Ascent);
    assert_eq!(VortexKind::AscentOut.duration_ms(), 2_000);
    game.apply(Event::AscentComplete).unwrap();
    assert!(game.is_ended());
}

#[test]
fn full_dive_bonus_requires_every_zone() {
    let mut progress = Progress::new();
    for z in Zone::ALL {
        progress.master_zone(z);
    }
    assert_eq!(
        progress.score(),
        trv_neural_mesh::progression::FULL_DIVE_BONUS
    );

    let mut partial = Progress::new();
    for z in &Zone::ALL[..Zone::ALL.len() - 1] {
        partial.master_zone(*z);
    }
    assert_eq!(partial.score(), 0); // no bonus without all five
}

#[test]
fn reduced_motion_setting_exists() {
    let s = VortexSettings::reduced();
    assert!(s.reduced_motion);
}
