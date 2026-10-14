//! Game state machine: menu → dive → neural zones → ascent.
//!
//! Every transition is explicit and fallible. Illegal transitions return
//! [`StateError`] instead of panicking or silently succeeding.

/// All phases of a Neural Mesh session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Title / disclaimer screen. Entry point of every session.
    Menu,
    /// Vortex dive into the neural landscape.
    Dive,
    /// Free exploration inside a brain zone.
    Zone,
    /// Educational challenge triggered by an anomaly.
    Challenge,
    /// Challenge resolved; rewards applied.
    Resolution,
    /// Vortex ascent back out; session summary.
    Ascent,
    /// Session ended (player quit or completed).
    Ended,
}

/// Events that drive the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Player acknowledged the disclaimer and pressed start.
    Start,
    /// Dive vortex finished; arrive in the first zone.
    DiveComplete,
    /// Player approached an anomaly; a challenge begins.
    AnomalyEncountered,
    /// Player answered the challenge.
    ChallengeAnswered { correct: bool },
    /// Rewards applied; back to exploring.
    ResolutionComplete,
    /// Player chose to ascend (or finished all zones).
    Ascend,
    /// Ascent vortex finished.
    AscentComplete,
    /// Player quit from menu, zone, or resolution.
    Quit,
}

/// Errors for illegal or impossible transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    /// The event is not valid in the current phase.
    IllegalTransition,
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StateError::IllegalTransition => write!(f, "event not valid in current phase"),
        }
    }
}

impl std::error::Error for StateError {}

/// The session state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Game {
    phase: Phase,
}

impl Game {
    /// A new session always starts at the menu (disclaimer screen).
    pub fn new() -> Self {
        Game { phase: Phase::Menu }
    }

    /// Current phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Apply an event. Returns the new phase, or [`StateError`] for an
    /// illegal transition (state is unchanged on error).
    pub fn apply(&mut self, event: Event) -> Result<Phase, StateError> {
        let next = match (self.phase, event) {
            (Phase::Menu, Event::Start) => Phase::Dive,
            (Phase::Menu, Event::Quit) => Phase::Ended,

            (Phase::Dive, Event::DiveComplete) => Phase::Zone,
            (Phase::Dive, Event::Quit) => Phase::Ended,

            (Phase::Zone, Event::AnomalyEncountered) => Phase::Challenge,
            (Phase::Zone, Event::Ascend) => Phase::Ascent,
            (Phase::Zone, Event::Quit) => Phase::Ended,

            (Phase::Challenge, Event::ChallengeAnswered { .. }) => Phase::Resolution,
            (Phase::Challenge, Event::Quit) => Phase::Ended,

            (Phase::Resolution, Event::ResolutionComplete) => Phase::Zone,
            (Phase::Resolution, Event::Ascend) => Phase::Ascent,
            (Phase::Resolution, Event::Quit) => Phase::Ended,

            (Phase::Ascent, Event::AscentComplete) => Phase::Ended,
            (Phase::Ascent, Event::Quit) => Phase::Ended,

            // Ended is terminal; nothing leaves it.
            _ => return Err(StateError::IllegalTransition),
        };
        self.phase = next;
        Ok(next)
    }

    /// True once the session has ended.
    pub fn is_ended(&self) -> bool {
        self.phase == Phase::Ended
    }
}

impl Default for Game {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_menu() {
        assert_eq!(Game::new().phase(), Phase::Menu);
        assert!(!Game::new().is_ended());
    }

    #[test]
    fn happy_path_full_session() {
        let mut g = Game::new();
        assert_eq!(g.apply(Event::Start), Ok(Phase::Dive));
        assert_eq!(g.apply(Event::DiveComplete), Ok(Phase::Zone));
        assert_eq!(g.apply(Event::AnomalyEncountered), Ok(Phase::Challenge));
        assert_eq!(
            g.apply(Event::ChallengeAnswered { correct: true }),
            Ok(Phase::Resolution)
        );
        assert_eq!(g.apply(Event::ResolutionComplete), Ok(Phase::Zone));
        assert_eq!(g.apply(Event::Ascend), Ok(Phase::Ascent));
        assert_eq!(g.apply(Event::AscentComplete), Ok(Phase::Ended));
        assert!(g.is_ended());
    }

    #[test]
    fn wrong_answer_still_resolves() {
        let mut g = Game::new();
        g.apply(Event::Start).unwrap();
        g.apply(Event::DiveComplete).unwrap();
        g.apply(Event::AnomalyEncountered).unwrap();
        // A wrong answer still moves to resolution (teaching moment),
        // just with fewer rewards — scoring lives in `progression`.
        assert_eq!(
            g.apply(Event::ChallengeAnswered { correct: false }),
            Ok(Phase::Resolution)
        );
    }

    #[test]
    fn quit_from_each_phase() {
        for (phase, setup) in [
            (Phase::Menu, vec![]),
            (Phase::Dive, vec![Event::Start]),
            (Phase::Zone, vec![Event::Start, Event::DiveComplete]),
            (
                Phase::Challenge,
                vec![
                    Event::Start,
                    Event::DiveComplete,
                    Event::AnomalyEncountered,
                ],
            ),
            (
                Phase::Resolution,
                vec![
                    Event::Start,
                    Event::DiveComplete,
                    Event::AnomalyEncountered,
                    Event::ChallengeAnswered { correct: true },
                ],
            ),
            (
                Phase::Ascent,
                vec![Event::Start, Event::DiveComplete, Event::Ascend],
            ),
        ] {
            let mut g = Game::new();
            for e in setup {
                g.apply(e).unwrap();
            }
            assert_eq!(g.phase(), phase);
            assert_eq!(g.apply(Event::Quit), Ok(Phase::Ended));
        }
    }

    #[test]
    fn illegal_transitions_fail_closed() {
        let mut g = Game::new();
        // Can't dive-complete from the menu.
        assert_eq!(
            g.apply(Event::DiveComplete),
            Err(StateError::IllegalTransition)
        );
        assert_eq!(g.phase(), Phase::Menu); // unchanged
        // Can't answer a challenge that was never encountered.
        assert_eq!(
            g.apply(Event::ChallengeAnswered { correct: true }),
            Err(StateError::IllegalTransition)
        );
        // Ended is terminal.
        g.apply(Event::Quit).unwrap();
        assert_eq!(g.apply(Event::Start), Err(StateError::IllegalTransition));
        assert_eq!(g.apply(Event::Quit), Err(StateError::IllegalTransition));
    }

    #[test]
    fn ascend_straight_from_resolution() {
        let mut g = Game::new();
        for e in [
            Event::Start,
            Event::DiveComplete,
            Event::AnomalyEncountered,
            Event::ChallengeAnswered { correct: true },
        ] {
            g.apply(e).unwrap();
        }
        assert_eq!(g.apply(Event::Ascend), Ok(Phase::Ascent));
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(
            format!("{}", StateError::IllegalTransition),
            "event not valid in current phase"
        );
    }
}
