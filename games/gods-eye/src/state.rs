//! Game state machine: menu -> briefing -> mission -> debrief.
//!
//! All transitions are explicit and validated. Illegal transitions are
//! rejected with an error rather than silently ignored, so the platform
//! layer can never put the game in an impossible state.

use crate::scoring::Score;
use crate::threats::Threat;

/// The four phases of a God's Eye session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Title screen. No mission loaded.
    Menu,
    /// Mission briefing shown; threats not yet active.
    Briefing,
    /// Live mission: threats spawn, the player responds.
    Mission,
    /// Mission over; results and lessons shown.
    Debrief,
}

/// What went wrong with a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    /// The requested transition is not legal from the current phase.
    IllegalTransition,
    /// No mission is loaded (needed for Briefing/Mission/Debrief).
    NoMission,
}

impl core::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransitionError::IllegalTransition => f.write_str("illegal phase transition"),
            TransitionError::NoMission => f.write_str("no mission loaded"),
        }
    }
}

impl std::error::Error for TransitionError {}

/// Difficulty tiers. Higher tiers spawn more simultaneous threats and
/// give the player less time to respond.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Difficulty {
    Cadet,
    Analyst,
    Sentinel,
}

impl Difficulty {
    /// Maximum simultaneous active threats.
    pub fn max_active_threats(self) -> u32 {
        match self {
            Difficulty::Cadet => 2,
            Difficulty::Analyst => 4,
            Difficulty::Sentinel => 7,
        }
    }

    /// Seconds the player has to respond to a threat before it escalates.
    pub fn response_window_secs(self) -> u64 {
        match self {
            Difficulty::Cadet => 45,
            Difficulty::Analyst => 25,
            Difficulty::Sentinel => 12,
        }
    }
}

/// A mission: a named scenario with a difficulty and a fixed roster of
/// threats that will appear during it.
#[derive(Debug, Clone)]
pub struct Mission {
    pub name: String,
    pub difficulty: Difficulty,
    /// Threat roster in spawn order (the engine may interleave).
    pub roster: Vec<Threat>,
    /// How long the mission lasts, in seconds.
    pub duration_secs: u64,
}

/// Configuration used to build a mission.
#[derive(Debug, Clone)]
pub struct MissionConfig {
    pub name: String,
    pub difficulty: Difficulty,
    pub roster: Vec<Threat>,
    pub duration_secs: u64,
}

impl Mission {
    pub fn new(cfg: MissionConfig) -> Self {
        Mission {
            name: cfg.name,
            difficulty: cfg.difficulty,
            roster: cfg.roster,
            duration_secs: cfg.duration_secs,
        }
    }
}

/// The full game state: current phase, loaded mission (if any),
/// elapsed mission time, and the running score.
#[derive(Debug)]
pub struct GameState {
    phase: Phase,
    mission: Option<Mission>,
    elapsed_secs: u64,
    score: Score,
}

impl GameState {
    pub fn new() -> Self {
        GameState {
            phase: Phase::Menu,
            mission: None,
            elapsed_secs: 0,
            score: Score::new(),
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn score(&self) -> &Score {
        &self.score
    }

    pub fn score_mut(&mut self) -> &mut Score {
        &mut self.score
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.elapsed_secs
    }

    /// Menu -> Briefing. Loads the mission.
    pub fn start_mission(&mut self, mission: Mission) -> Result<(), TransitionError> {
        if self.phase != Phase::Menu {
            return Err(TransitionError::IllegalTransition);
        }
        self.mission = Some(mission);
        self.elapsed_secs = 0;
        self.score = Score::new();
        self.phase = Phase::Briefing;
        Ok(())
    }

    /// Briefing -> Mission. The briefing has been read; threats go live.
    pub fn begin_mission(&mut self) -> Result<(), TransitionError> {
        if self.phase != Phase::Briefing {
            return Err(TransitionError::IllegalTransition);
        }
        if self.mission.is_none() {
            return Err(TransitionError::NoMission);
        }
        self.phase = Phase::Mission;
        Ok(())
    }

    /// Advance mission time. When the clock runs out, the mission ends
    /// and the game moves to Debrief automatically.
    pub fn tick(&mut self, secs: u64) -> Result<(), TransitionError> {
        if self.phase != Phase::Mission {
            return Err(TransitionError::IllegalTransition);
        }
        let mission = self.mission.as_ref().ok_or(TransitionError::NoMission)?;
        self.elapsed_secs = self.elapsed_secs.saturating_add(secs);
        if self.elapsed_secs >= mission.duration_secs {
            self.phase = Phase::Debrief;
        }
        Ok(())
    }

    /// Debrief -> Menu. The session is over; the mission is unloaded.
    pub fn finish(&mut self) -> Result<(), TransitionError> {
        if self.phase != Phase::Debrief {
            return Err(TransitionError::IllegalTransition);
        }
        self.mission = None;
        self.elapsed_secs = 0;
        self.phase = Phase::Menu;
        Ok(())
    }

    /// Abort from Briefing or Mission back to Menu (mission discarded).
    pub fn abort(&mut self) -> Result<(), TransitionError> {
        match self.phase {
            Phase::Briefing | Phase::Mission => {
                self.mission = None;
                self.elapsed_secs = 0;
                self.phase = Phase::Menu;
                Ok(())
            }
            Phase::Menu | Phase::Debrief => Err(TransitionError::IllegalTransition),
        }
    }

    pub fn mission(&self) -> Option<&Mission> {
        self.mission.as_ref()
    }
}

impl Default for GameState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threats::{Threat, ThreatKind};

    fn test_mission() -> Mission {
        Mission::new(MissionConfig {
            name: "Test Op".to_string(),
            difficulty: Difficulty::Cadet,
            roster: vec![Threat::new(1, ThreatKind::Phishing)],
            duration_secs: 60,
        })
    }

    #[test]
    fn full_session_flow() {
        let mut g = GameState::new();
        assert_eq!(g.phase(), Phase::Menu);
        g.start_mission(test_mission()).unwrap();
        assert_eq!(g.phase(), Phase::Briefing);
        g.begin_mission().unwrap();
        assert_eq!(g.phase(), Phase::Mission);
        g.tick(30).unwrap();
        assert_eq!(g.phase(), Phase::Mission);
        g.tick(30).unwrap();
        assert_eq!(g.phase(), Phase::Debrief);
        g.finish().unwrap();
        assert_eq!(g.phase(), Phase::Menu);
        assert!(g.mission().is_none());
    }

    #[test]
    fn illegal_transitions_rejected() {
        let mut g = GameState::new();
        // Can't begin without briefing.
        assert_eq!(g.begin_mission(), Err(TransitionError::IllegalTransition));
        // Can't tick outside a mission.
        assert_eq!(g.tick(10), Err(TransitionError::IllegalTransition));
        // Can't finish outside debrief.
        assert_eq!(g.finish(), Err(TransitionError::IllegalTransition));
        // Can't start a second mission while briefing the first.
        g.start_mission(test_mission()).unwrap();
        assert_eq!(
            g.start_mission(test_mission()),
            Err(TransitionError::IllegalTransition)
        );
    }

    #[test]
    fn abort_returns_to_menu() {
        let mut g = GameState::new();
        g.start_mission(test_mission()).unwrap();
        g.abort().unwrap();
        assert_eq!(g.phase(), Phase::Menu);

        g.start_mission(test_mission()).unwrap();
        g.begin_mission().unwrap();
        g.abort().unwrap();
        assert_eq!(g.phase(), Phase::Menu);
        // Can't abort from menu.
        assert_eq!(g.abort(), Err(TransitionError::IllegalTransition));
    }

    #[test]
    fn tick_overflow_is_safe() {
        let mut g = GameState::new();
        g.start_mission(test_mission()).unwrap();
        g.begin_mission().unwrap();
        g.tick(u64::MAX).unwrap();
        assert_eq!(g.phase(), Phase::Debrief);
        assert_eq!(g.elapsed_secs(), u64::MAX);
    }

    #[test]
    fn difficulty_tuning() {
        assert!(Difficulty::Cadet.max_active_threats() < Difficulty::Sentinel.max_active_threats());
        assert!(Difficulty::Cadet.response_window_secs() > Difficulty::Sentinel.response_window_secs());
    }
}
