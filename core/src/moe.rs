//! On-device Mixture-of-Experts router.
//!
//! Routes queries to the 11 on-device expert skills. Routing is
//! keyword-based and fully deterministic: no model weights, no cloud,
//! no I/O. All routing is local — nothing ever touches the network.

/// The 11 on-device expert skills.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpertSkill {
    CognitiveScience,
    Coordinator,
    DeclassifiedOps,
    FirstAid,
    Mathematics,
    Physics,
    PoliticalScience,
    Quantum,
    RemoteViewer,
    SimpleComms,
    Zk,
}

impl ExpertSkill {
    /// All 11 experts, in canonical order.
    pub fn all() -> [ExpertSkill; 11] {
        [
            ExpertSkill::CognitiveScience,
            ExpertSkill::Coordinator,
            ExpertSkill::DeclassifiedOps,
            ExpertSkill::FirstAid,
            ExpertSkill::Mathematics,
            ExpertSkill::Physics,
            ExpertSkill::PoliticalScience,
            ExpertSkill::Quantum,
            ExpertSkill::RemoteViewer,
            ExpertSkill::SimpleComms,
            ExpertSkill::Zk,
        ]
    }

    /// Canonical skill name (kebab-case, stable across releases).
    pub fn name(self) -> &'static str {
        match self {
            ExpertSkill::CognitiveScience => "cognitive-science",
            ExpertSkill::Coordinator => "coordinator",
            ExpertSkill::DeclassifiedOps => "declassified-ops",
            ExpertSkill::FirstAid => "first-aid",
            ExpertSkill::Mathematics => "mathematics",
            ExpertSkill::Physics => "physics",
            ExpertSkill::PoliticalScience => "political-science",
            ExpertSkill::Quantum => "quantum",
            ExpertSkill::RemoteViewer => "remote-viewer",
            ExpertSkill::SimpleComms => "simple-comms",
            ExpertSkill::Zk => "zk",
        }
    }
}

/// Keyword sets used by the router, in priority order. When several
/// experts match, the one with the most keyword hits wins; ties break
/// to whichever appears earlier in this list. Most specific domains
/// come first so ambiguous input resolves deterministically.
///
/// Matching rule (see [`keyword_matches`]): a keyword that is a single
/// alphanumeric word must appear as a *whole word* in the input
/// (words are split on non-alphanumeric boundaries), so short tokens
/// like `zk` no longer fire inside longer words like "waterproof".
/// Keywords containing separators (spaces, hyphens, dots) keep
/// substring matching — the separators already make them specific.
const ROUTING_TABLE: &[(ExpertSkill, &[&str])] = &[
    (ExpertSkill::Zk, &[
        "zero-knowledge", "zero knowledge", "zk",
        "zk-snark", "snark", "zk-stark", "stark", "proof", "verify",
        "cryptography", "cryptographic", "encrypt", "commitment",
    ]),
    (ExpertSkill::Quantum, &[
        "quantum", "qubit", "superposition", "entanglement", "entangle",
        "tunneling", "uncertainty principle", "wavefunction",
        "schrodinger", "schrödinger",
    ]),
    (ExpertSkill::FirstAid, &[
        "first aid", "first-aid", "firstaid", "injury", "bleed", "bleeding",
        "cpr", "choking", "heimlich", "burn", "wound", "fracture",
        "sprain", "shock", "tourniquet", "resuscitat", "epipen",
    ]),
    (ExpertSkill::DeclassifiedOps, &[
        "declassified", "foia", "freedom of information", "cia", "fbi",
        "classified", "redact", "leak", "whistleblower", "operation north",
        "mkultra", "mk-ultra", "project ",
    ]),
    (ExpertSkill::RemoteViewer, &[
        "remote view", "remote-view", "remoteview", "gateway", "focus 10",
        "focus 12", "focus 15", "focus 21", "focus 27", "resonant tuning",
        "hemi-sync", "hemisync", "binaural", "out-of-body", "astral",
        "crv", "erv", "coordinate remote",
    ]),
    (ExpertSkill::SimpleComms, &[
        "qr code", "qr", "nfc", "signal", "radio", "bluetooth",
        "proximity", "airgap", "air-gap", "transmit", "receive",
        "antenna", "mesh",
    ]),
    (ExpertSkill::Mathematics, &[
        "math", "equation", "calculate", "calculation", "algebra",
        "calculus", "geometry", "theorem", "integral", "derivative",
        "matrix", "statistic", "probability", "formula", "solve for",
    ]),
    (ExpertSkill::Physics, &[
        "physics", "gravity", "gravit", "velocity", "acceleration",
        "relativity", "relativistic", "newton", "einstein", "momentum",
        "thermodynamics", "electromagnet", "particle", "boson",
        "fermion", "string theory",
    ]),
    (ExpertSkill::PoliticalScience, &[
        "election", "policy", "government", "vote", "voting", "senate",
        "congress", "parliament", "democracy", "republic", "campaign",
        "legislat", "constitution", "amendment", "diplomac", "treaty",
        "geopolitic", "sovereignty",
    ]),
    (ExpertSkill::CognitiveScience, &[
        "memory", "cognition", "cognitive", "bias", "learning",
        "neuroscience", "brain", "perception", "attention", "psychology",
        "heuristic", "recall", "dream", "consciousness", "neural",
    ]),
];

/// True when `word` appears in `haystack` as a whole word.
///
/// `haystack` is split on non-alphanumeric boundaries, so a short
/// token like `zk` matches "zk-snark" (words: "zk", "snark") but not
/// "waterproof". No case folding here — callers lowercase first.
fn contains_word(haystack: &str, word: &str) -> bool {
    haystack
        .split(|c: char| !c.is_alphanumeric())
        .any(|w| w == word)
}

/// True when the keyword `kw` matches the (already lowercased) input.
///
/// Single-word keywords — one run of ASCII alphanumerics — must match
/// a whole word (see [`contains_word`]); this is what keeps short
/// tokens like `zk` from firing inside longer words. Keywords that
/// contain separators (spaces, hyphens, dots) keep plain substring
/// matching, since the separators already make them specific enough.
fn keyword_matches(lowered: &str, kw: &str) -> bool {
    if kw.chars().all(|c| c.is_ascii_alphanumeric()) {
        contains_word(lowered, kw)
    } else {
        lowered.contains(kw)
    }
}

/// Route free-text input to the best local expert using
/// case-insensitive keyword matching.
///
/// * A single-word keyword matches only whole words, so short tokens
///   (e.g. `zk`) never fire inside longer words (e.g. "waterproof").
/// * Multi-token keywords (spaces, hyphens, dots) match substrings.
/// * The expert with the most keyword hits wins.
/// * Ties break to the most specific domain first (priority order in
///   [`ROUTING_TABLE`]).
/// * [`ExpertSkill::Coordinator`] is the default when nothing matches
///   (including empty input).
///
/// Pure computation — no I/O, no network.
pub fn route(input: &str) -> ExpertSkill {
    let lowered = input.to_ascii_lowercase();

    let mut best: Option<(ExpertSkill, usize)> = None;
    for &(skill, keywords) in ROUTING_TABLE {
        let mut hits = 0usize;
        for &kw in keywords {
            if keyword_matches(&lowered, kw) {
                hits += 1;
            }
        }
        if hits > 0 {
            match best {
                Some((_, best_hits)) if best_hits >= hits => {}
                _ => best = Some((skill, hits)),
            }
        }
    }

    best.map(|(skill, _)| skill).unwrap_or(ExpertSkill::Coordinator)
}

/// Local MoE router. Wraps the keyword gate; real model-weight gates
/// would consult local rules/skill-index here. Never the network.
#[derive(Debug, Default)]
pub struct MoeRouter;

impl MoeRouter {
    /// Create a new local MoE router. No weights, no I/O.
    pub fn new() -> Self {
        MoeRouter
    }

    /// Route a request to the best local expert skill.
    ///
    /// Deterministic keyword gate (see [`route`]); a future
    /// weight-based gate keeps this signature. No network.
    pub fn route(&self, request: &str) -> ExpertSkill {
        route(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_routes(input: &str, expected: ExpertSkill) {
        assert_eq!(
            route(input),
            expected,
            "input {:?} routed to {:?}, expected {:?}",
            input,
            route(input),
            expected
        );
    }

    #[test]
    fn routes_to_zk() {
        assert_routes("how does a zero-knowledge proof work?", ExpertSkill::Zk);
        assert_routes("Verify this zk-SNARK on device", ExpertSkill::Zk);
    }

    #[test]
    fn routes_to_quantum() {
        assert_routes("explain qubit superposition", ExpertSkill::Quantum);
        assert_routes("QUANTUM ENTANGLEMENT demo", ExpertSkill::Quantum);
    }

    #[test]
    fn routes_to_first_aid() {
        assert_routes("How do I do CPR on an adult?", ExpertSkill::FirstAid);
        assert_routes("severe bleeding from an injury, first aid steps", ExpertSkill::FirstAid);
    }

    #[test]
    fn routes_to_declassified_ops() {
        assert_routes("File a FOIA request for declassified CIA documents", ExpertSkill::DeclassifiedOps);
        assert_routes("What do the declassified files say?", ExpertSkill::DeclassifiedOps);
    }

    #[test]
    fn routes_to_remote_viewer() {
        assert_routes("Guide me through a remote viewing session at Focus 10", ExpertSkill::RemoteViewer);
        assert_routes("What is the gateway process?", ExpertSkill::RemoteViewer);
    }

    #[test]
    fn routes_to_simple_comms() {
        assert_routes("Share contact via QR code", ExpertSkill::SimpleComms);
        assert_routes("pair over NFC and radio signal", ExpertSkill::SimpleComms);
    }

    #[test]
    fn routes_to_mathematics() {
        assert_routes("solve this algebra equation step by step", ExpertSkill::Mathematics);
        assert_routes("Calculate the integral of x^2", ExpertSkill::Mathematics);
    }

    #[test]
    fn routes_to_physics() {
        assert_routes("Explain gravity and velocity in physics terms", ExpertSkill::Physics);
        assert_routes("newton's laws of motion", ExpertSkill::Physics);
    }

    #[test]
    fn routes_to_political_science() {
        assert_routes("How does the election policy process work in government?", ExpertSkill::PoliticalScience);
        assert_routes("senate vote on the treaty", ExpertSkill::PoliticalScience);
    }

    #[test]
    fn routes_to_cognitive_science() {
        assert_routes("How does memory and learning work?", ExpertSkill::CognitiveScience);
        assert_routes("cognitive bias in decision making", ExpertSkill::CognitiveScience);
    }

    #[test]
    fn routes_to_coordinator_as_default() {
        // Unmatched chit-chat goes to the coordinator.
        assert_routes("hello, how are you?", ExpertSkill::Coordinator);
        assert_routes("tell me a joke", ExpertSkill::Coordinator);
        assert_routes("Coordinator fallback on plain text", ExpertSkill::Coordinator);
    }

    #[test]
    fn empty_and_whitespace_input_fall_back_to_coordinator() {
        assert_routes("", ExpertSkill::Coordinator);
        assert_routes("   ", ExpertSkill::Coordinator);
        assert_routes("\n\t", ExpertSkill::Coordinator);
    }

    #[test]
    fn case_insensitive_matching() {
        assert_routes("CALCULATE MY TAXES", ExpertSkill::Mathematics);
        assert_routes("Cpr Instructions Please", ExpertSkill::FirstAid);
        assert_routes("QuAnTuM PhYsIcS", ExpertSkill::Quantum);
    }

    #[test]
    fn ambiguous_input_has_deterministic_winner() {
        // Both "quantum" and "physics" appear; quantum is the more
        // specific domain and wins regardless of word order.
        assert_routes("quantum physics primer", ExpertSkill::Quantum);
        assert_routes("physics of quantum systems", ExpertSkill::Quantum);
        // Same input routed twice must agree.
        let a = route("signal boost for the radio mesh");
        let b = route("signal boost for the radio mesh");
        assert_eq!(a, b);
        assert_eq!(a, ExpertSkill::SimpleComms);
    }

    #[test]
    fn more_keyword_hits_beats_priority_order() {
        // Three math keywords outnumber one quantum keyword, so math wins
        // even though quantum has higher priority.
        assert_routes(
            "calculate the equation and solve for x using algebra, quantum footnote",
            ExpertSkill::Mathematics,
        );
    }

    #[test]
    fn waterproof_does_not_route_to_zk() {
        // Regression: the old bare-substring "zk" fired inside
        // "waterproof" (and "proof" did too). Word-aware matching
        // keeps the jacket out of the cryptography expert.
        assert_routes("is this jacket waterproof enough for rain?", ExpertSkill::Coordinator);
        assert_routes("waterproof boots for the trail", ExpertSkill::Coordinator);
        // The standalone token still routes to zk.
        assert_routes("explain zk proofs in simple terms", ExpertSkill::Zk);
        assert_routes("what is a zk-SNARK?", ExpertSkill::Zk);
    }

    #[test]
    fn router_struct_delegates_to_free_function() {        let router = MoeRouter::new();
        assert_eq!(router.route("bleeding wound first aid"), ExpertSkill::FirstAid);
        assert_eq!(router.route(""), ExpertSkill::Coordinator);
    }

    #[test]
    fn all_eleven_experts_still_listed() {
        let all = ExpertSkill::all();
        assert_eq!(all.len(), 11);
        assert!(all.contains(&ExpertSkill::Coordinator));
    }
}
