//! Interactive, on-device educational Gateway Process module.
//!
//! EDUCATIONAL PURPOSES ONLY. This module provides a guided,
//! step-by-step study flow through the *concepts* described in the
//! declassified Gateway Process literature (focus states, resonance,
//! hemi-sync ideas). It is a local interactive state machine: the
//! caller advances through prompts and tracks progress on-device.
//!
//! It makes no claims of efficacy, performs no sensing, and does no
//! network I/O. Everything is local, on-device, and zero-dependency.

/// Focus states discussed in Gateway Process literature, modeled as
/// labels for study. These are descriptions of reported subjective
/// states, not measurements or promises of outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FocusState {
    /// Focus 10: "mind awake, body asleep" — reported deep relaxation
    /// with maintained awareness.
    Focus10,
    /// Focus 12: expanded awareness beyond physical senses.
    Focus12,
    /// Focus 15: "no time" — timelessness in reported experience.
    Focus15,
    /// Focus 21: the threshold/borderland state between sleep and
    /// wakefulness in the literature.
    Focus21,
}

impl FocusState {
    /// All focus states, in canonical order.
    pub fn all() -> [FocusState; 4] {
        [
            FocusState::Focus10,
            FocusState::Focus12,
            FocusState::Focus15,
            FocusState::Focus21,
        ]
    }

    /// Canonical label used in the literature.
    pub fn label(self) -> &'static str {
        match self {
            FocusState::Focus10 => "Focus 10",
            FocusState::Focus12 => "Focus 12",
            FocusState::Focus15 => "Focus 15",
            FocusState::Focus21 => "Focus 21",
        }
    }

    /// Educational description of what the literature reports about
    /// this state. Descriptive of the material, not an instruction.
    pub fn description(self) -> &'static str {
        match self {
            FocusState::Focus10 => {
                "Reported as mind-awake/body-asleep: deep physical relaxation while remaining aware."
            }
            FocusState::Focus12 => {
                "Reported as expanded awareness: perception described as extending beyond physical senses."
            }
            FocusState::Focus15 => {
                "Reported as no-time: the sense of time described as falling away in the literature."
            }
            FocusState::Focus21 => {
                "Reported as the borderland between sleep and waking, explored as a gateway state."
            }
        }
    }

    /// A short reflection prompt shown when the user studies this
    /// state. Educational only.
    pub fn prompt(self) -> &'static str {
        match self {
            FocusState::Focus10 => {
                "Read about Focus 10. What does the literature say distinguishes it from ordinary rest?"
            }
            FocusState::Focus12 => {
                "Read about Focus 12. How does the material describe 'expanded awareness'?"
            }
            FocusState::Focus15 => {
                "Read about Focus 15. What does the literature mean by 'no time'?"
            }
            FocusState::Focus21 => {
                "Read about Focus 21. Why does the material call it a borderland state?"
            }
        }
    }
}

/// Core concepts from the Gateway Process material, modeled as
/// study topics. Each carries an educational description only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatewayConcept {
    /// Hemi-Sync: the binaural-beat technique described in the
    /// literature as encouraging hemispheric synchronization.
    HemiSync,
    /// Resonance: the idea of aligning with coherent patterns,
    /// as discussed in the material.
    Resonance,
    /// The "click-out": reported shifts in consciousness described
    /// in the literature.
    ClickOut,
    /// Patterning: goal-setting / intent described as a mental
    /// focusing exercise in the material.
    Patterning,
    /// Energy conversion: the body-as-transducer concept in the
    /// literature (converting physical energy to mental focus).
    EnergyConversion,
    /// Remote viewing: perceiving at a distance, as discussed in
    /// the declassified literature and research programs.
    RemoteViewing,
}

impl GatewayConcept {
    /// All gateway concepts, in canonical order.
    pub fn all() -> [GatewayConcept; 6] {
        [
            GatewayConcept::HemiSync,
            GatewayConcept::Resonance,
            GatewayConcept::ClickOut,
            GatewayConcept::Patterning,
            GatewayConcept::EnergyConversion,
            GatewayConcept::RemoteViewing,
        ]
    }

    /// Canonical name.
    pub fn name(self) -> &'static str {
        match self {
            GatewayConcept::HemiSync => "hemi-sync",
            GatewayConcept::Resonance => "resonance",
            GatewayConcept::ClickOut => "click-out",
            GatewayConcept::Patterning => "patterning",
            GatewayConcept::EnergyConversion => "energy-conversion",
            GatewayConcept::RemoteViewing => "remote-viewing",
        }
    }

    /// Educational description of the concept as presented in the
    /// literature. Descriptive, not instructional.
    pub fn description(self) -> &'static str {
        match self {
            GatewayConcept::HemiSync => {
                "Binaural audio technique described as encouraging the brain's hemispheres to work together."
            }
            GatewayConcept::Resonance => {
                "The idea of attuning one's focus to coherent, stable patterns."
            }
            GatewayConcept::ClickOut => {
                "Reported shifts in awareness described as momentary 'clicks' to another state."
            }
            GatewayConcept::Patterning => {
                "A focusing exercise: clearly forming an intention and holding it in mind."
            }
            GatewayConcept::EnergyConversion => {
                "The literature's model of the body converting physical energy into focused awareness."
            }
            GatewayConcept::RemoteViewing => {
                "Perceiving distant or unseen targets, as explored in declassified research programs."
            }
        }
    }

    /// A short reflection prompt shown when the user studies this
    /// concept. Educational only.
    pub fn prompt(self) -> &'static str {
        match self {
            GatewayConcept::HemiSync => {
                "What does the literature claim hemi-sync audio is meant to encourage?"
            }
            GatewayConcept::Resonance => {
                "In your own words, what does 'resonance' mean in this material?"
            }
            GatewayConcept::ClickOut => {
                "How does the literature describe a 'click-out' experience?"
            }
            GatewayConcept::Patterning => {
                "What role does clearly formed intention play in the patterning exercise?"
            }
            GatewayConcept::EnergyConversion => {
                "How does the material model the body as a transducer of energy?"
            }
            GatewayConcept::RemoteViewing => {
                "What did the declassified research programs report about remote viewing?"
            }
        }
    }
}

/// One interactive step in a guided study session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStep {
    /// Introduction to the session and the material.
    Intro,
    /// Study a focus state.
    State(FocusState),
    /// Study a gateway concept.
    Concept(GatewayConcept),
    /// Reflection: review what was covered.
    Reflection,
}

impl SessionStep {
    /// The prompt shown to the user for this step. All strings are
    /// local constants — no I/O.
    pub fn prompt(self) -> String {
        match self {
            SessionStep::Intro => String::from(
                "Welcome to the Gateway Process study session (educational). \
                 You will step through focus states and key concepts from the \
                 declassified literature. Take your time; there is no timer.",
            ),
            SessionStep::State(s) => {
                format!("{} — {}\nPrompt: {}", s.label(), s.description(), s.prompt())
            }
            SessionStep::Concept(c) => {
                format!("{} — {}\nPrompt: {}", c.name(), c.description(), c.prompt())
            }
            SessionStep::Reflection => String::from(
                "Reflection: which focus state and which concept stood out most, \
                 and why? Your notes stay on this device.",
            ),
        }
    }
}

/// The interactive session state machine. The caller (a future native
/// UI) drives it: read `current_prompt()`, then call `advance()` when
/// the user is ready, or `go_back()` to revisit. Progress is tracked
/// locally in memory.
#[derive(Debug, Clone)]
pub struct GuidedSession {
    steps: Vec<SessionStep>,
    index: usize,
    /// Steps the user has completed, in visit order (local only).
    completed: Vec<SessionStep>,
}

impl GuidedSession {
    /// Build the default guided session: intro, all focus states,
    /// all concepts, then reflection.
    pub fn new() -> Self {
        let mut steps = vec![SessionStep::Intro];
        for s in FocusState::all() {
            steps.push(SessionStep::State(s));
        }
        for c in GatewayConcept::all() {
            steps.push(SessionStep::Concept(c));
        }
        steps.push(SessionStep::Reflection);
        GuidedSession {
            steps,
            index: 0,
            completed: Vec::new(),
        }
    }

    /// Build a custom session from a chosen step list.
    pub fn custom(steps: Vec<SessionStep>) -> Self {
        GuidedSession {
            steps,
            index: 0,
            completed: Vec::new(),
        }
    }

    /// Total number of steps in this session.
    pub fn total_steps(&self) -> usize {
        self.steps.len()
    }

    /// Current step, or `None` if the session is complete.
    pub fn current(&self) -> Option<SessionStep> {
        self.steps.get(self.index).copied()
    }

    /// The prompt for the current step, or `None` when complete.
    pub fn current_prompt(&self) -> Option<String> {
        self.current().map(|s| s.prompt())
    }

    /// Advance to the next step. Records the finished step locally.
    /// Returns `true` if there is a next step, `false` when the
    /// session is now complete.
    pub fn advance(&mut self) -> bool {
        if let Some(step) = self.steps.get(self.index).copied() {
            self.completed.push(step);
            self.index += 1;
        }
        self.index < self.steps.len()
    }

    /// Go back one step (the step is un-marked as completed).
    /// Returns `true` if moved back, `false` if already at the start.
    pub fn go_back(&mut self) -> bool {
        if self.index == 0 {
            return false;
        }
        self.index -= 1;
        self.completed.pop();
        true
    }

    /// Restart the session from the beginning, clearing progress.
    pub fn reset(&mut self) {
        self.index = 0;
        self.completed.clear();
    }

    /// True when every step has been completed.
    pub fn is_complete(&self) -> bool {
        self.index >= self.steps.len()
    }

    /// Progress as a fraction 0.0–1.0.
    pub fn progress(&self) -> f64 {
        if self.steps.is_empty() {
            return 1.0;
        }
        self.completed.len() as f64 / self.steps.len() as f64
    }

    /// Number of completed steps.
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }
}

impl Default for GuidedSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_session_has_twelve_steps_in_expected_order() {
        let session = GuidedSession::new();
        assert_eq!(session.total_steps(), 12);
        assert_eq!(session.current(), Some(SessionStep::Intro));
        assert_eq!(session.completed_count(), 0);
        assert_eq!(session.progress(), 0.0);
        assert!(!session.is_complete());
    }

    #[test]
    fn advance_drives_progress_zero_to_one_and_completes_at_end() {
        let mut session = GuidedSession::new();
        let mut saw_state = false;
        let mut saw_concept = false;

        for _ in 0..11 {
            assert!(!session.is_complete());
            let advanced = session.advance();
            assert!(advanced, "should still have a next step");
            assert!(session.current_prompt().is_some());
        }
        // After 11 advances the current step is the reflection.
        assert_eq!(
            session.current(),
            Some(SessionStep::Reflection),
            "expected Reflection as the last step"
        );
        // Completing the last step leaves no next step: advance() reports
        // false once the final step is consumed, and the session is complete.
        assert!(!session.advance(), "completing the last step leaves no next step");
        assert!(session.is_complete());
        assert!(!session.advance(), "advance past the end reports no next step");
        assert_eq!(session.progress(), 1.0);
        assert_eq!(session.completed_count(), 12);
        assert!(session.current().is_none());
        assert!(session.current_prompt().is_none());

        // Confirm states and concepts were visited along the way.
        let mut replay = GuidedSession::new();
        while !replay.is_complete() {
            match replay.current() {
                Some(SessionStep::State(_)) => saw_state = true,
                Some(SessionStep::Concept(_)) => saw_concept = true,
                _ => {}
            }
            replay.advance();
        }
        assert!(saw_state && saw_concept);
    }

    #[test]
    fn go_back_regresses_and_is_false_at_start() {
        let mut session = GuidedSession::new();
        assert!(!session.go_back(), "go_back at the start must fail");

        assert!(session.advance());
        assert!(session.advance());
        assert_eq!(session.completed_count(), 2);
        let before = session.progress();

        assert!(session.go_back());
        assert_eq!(session.completed_count(), 1);
        assert!(session.progress() < before);
        assert_eq!(session.current(), Some(SessionStep::State(FocusState::Focus10)));

        // Re-advancing restores the completed step.
        assert!(session.advance());
        assert_eq!(session.completed_count(), 2);
    }

    #[test]
    fn reset_restarts_session_and_clears_progress() {
        let mut session = GuidedSession::new();
        for _ in 0..5 {
            session.advance();
        }
        session.reset();
        assert_eq!(session.completed_count(), 0);
        assert_eq!(session.progress(), 0.0);
        assert!(!session.is_complete());
        assert_eq!(session.current(), Some(SessionStep::Intro));
    }

    #[test]
    fn focus_states_and_concepts_have_distinct_nonempty_content() {
        let mut labels = std::collections::HashSet::new();
        for state in FocusState::all() {
            assert!(!state.label().is_empty());
            assert!(!state.description().is_empty());
            assert!(!state.prompt().is_empty());
            assert!(labels.insert(state.label()));
        }

        let mut names = std::collections::HashSet::new();
        for concept in GatewayConcept::all() {
            assert!(!concept.name().is_empty());
            assert!(!concept.description().is_empty());
            assert!(!concept.prompt().is_empty());
            assert!(names.insert(concept.name()));
        }
    }

    #[test]
    fn custom_session_uses_given_steps() {
        let steps = vec![
            SessionStep::Intro,
            SessionStep::State(FocusState::Focus21),
            SessionStep::Reflection,
        ];
        let mut session = GuidedSession::custom(steps);
        assert_eq!(session.total_steps(), 3);
        while !session.is_complete() {
            session.advance();
        }
        assert_eq!(session.completed_count(), 3);
        assert_eq!(session.progress(), 1.0);
    }
}
