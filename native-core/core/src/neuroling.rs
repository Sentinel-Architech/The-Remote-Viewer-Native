//! Neurolinguistics-inspired on-device language signals for The Remote Viewer.
//!
//! User goal (2026-10-13): neurolinguistics of all sorts in the DApp, aimed
//! at helping humanity connect with others instead of doomscrolling.
//!
//! **Honest scope.** This module is applied on-device *text heuristics*:
//! word counts, lexical diversity, punctuation patterns, a small hand-written
//! sentiment lexicon, and conversation-balance math. It is NOT brain
//! imaging, NOT a clinical measure, NOT neurology, and NOT a learned model.
//! There are no ML weights, no external dependencies, and no network I/O
//! anywhere in this crate. Everything here is pure computation over text the
//! viewer already holds on-device.
//!
//! The product philosophy encoded here: **optimize for real connection, not
//! time-on-screen.** [`connection_score`] ranks feed content that invites
//! meaningful exchange — balanced back-and-forth, substantive messages,
//! cited sources, mutual follows — above doomscroll signals such as outrage
//! bait and rapid shallow items. Nothing here decides what a viewer may see;
//! it only orders, transparently, on-device.

/// Hand-written positive sentiment lexicon. Small and deliberately plain;
/// a rough heuristic signal, not a clinical measure of anyone's feelings.
const POSITIVE_WORDS: &[&str] = &[
    "amazing", "awesome", "beautiful", "blessed", "brave", "bright", "brilliant",
    "care", "caring", "celebrate", "community", "congratulations", "courage",
    "excellent", "excited", "friend", "friendly", "fun", "glad", "good",
    "grateful", "great", "happy", "heal", "healing", "help", "helpful",
    "honest", "hope", "hopeful", "inspire", "inspiring", "joy", "joyful",
    "kind", "laugh", "light", "love", "peace", "peaceful", "proud", "recover",
    "respect", "smile", "strong", "support", "supportive", "thank", "thanks",
    "together", "trust", "truth", "unite", "unity", "welcome", "win",
    "winning", "wonderful",
];

/// Hand-written negative sentiment lexicon. Same caveats as
/// [`POSITIVE_WORDS`]: a rough heuristic, not a diagnosis.
const NEGATIVE_WORDS: &[&str] = &[
    "afraid", "angry", "attack", "awful", "blame", "cheat", "corrupt",
    "corruption", "cry", "death", "destroy", "die", "disgusting", "doom",
    "dumb", "evil", "fail", "failure", "fake", "fear", "fraud", "furious",
    "hate", "hopeless", "horrible", "hurt", "kill", "liar", "lie", "lies",
    "loser", "pain", "pathetic", "rage", "ruin", "ruined", "sad", "scam",
    "scared", "shame", "shameful", "steal", "stupid", "suffering", "terrible",
    "ugly", "vile", "war", "worst",
];

/// Split text into lowercase word tokens, stripping surrounding punctuation.
/// Tokens with no alphanumeric characters are dropped.
fn tokens(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase()
        })
        .filter(|w| w.chars().any(|c| c.is_alphanumeric()))
        .collect()
}

/// Structural signals computed from a single text sample.
///
/// All fields are descriptive statistics of the text itself. They say nothing
/// about the author's brain, only about the shape of the message.
#[derive(Debug, Clone, Copy)]
pub struct TextSignals {
    /// Number of word tokens.
    pub word_count: u32,
    /// Unique tokens / total tokens, 0.0..=1.0. Higher means more varied
    /// vocabulary in the sample. Empty text yields 0.0.
    pub unique_word_ratio: f32,
    /// Number of `?` characters.
    pub question_count: u32,
    /// Number of `!` characters.
    pub exclamation_count: u32,
    /// Mean token length in characters. Empty text yields 0.0.
    pub avg_word_len: f32,
}

impl TextSignals {
    /// Compute signals for `text`. Pure function; no I/O.
    pub fn analyze(text: &str) -> Self {
        let toks = tokens(text);
        let word_count = toks.len() as u32;
        let unique_word_ratio = if toks.is_empty() {
            0.0
        } else {
            let mut uniq: Vec<&str> = toks.iter().map(|s| s.as_str()).collect();
            uniq.sort_unstable();
            uniq.dedup();
            uniq.len() as f32 / toks.len() as f32
        };
        let question_count = text.chars().filter(|&c| c == '?').count() as u32;
        let exclamation_count = text.chars().filter(|&c| c == '!').count() as u32;
        let avg_word_len = if toks.is_empty() {
            0.0
        } else {
            toks.iter().map(|t| t.chars().count() as f32).sum::<f32>()
                / toks.len() as f32
        };
        TextSignals {
            word_count,
            unique_word_ratio,
            question_count,
            exclamation_count,
            avg_word_len,
        }
    }
}

/// Rough sentiment heuristic, -100 (negative) to 100 (positive).
///
/// Counts hits against the small built-in positive/negative lexicons and
/// scales the net count. This is a blunt instrument: sarcasm, context, and
/// negation ("not good") are not understood. Treat the result as a vague
/// leaning, never as a measurement of anyone's mental state.
pub fn sentiment_heuristic(text: &str) -> i8 {
    let mut net: i32 = 0;
    for tok in tokens(text) {
        if POSITIVE_WORDS.contains(&tok.as_str()) {
            net += 1;
        }
        if NEGATIVE_WORDS.contains(&tok.as_str()) {
            net -= 1;
        }
    }
    // Each net lexicon hit moves the needle 20 points; clamp to range.
    (net * 20).clamp(-100, 100) as i8
}

/// Count crude outrage-bait signals in `text`: words in ALL CAPS (length >= 3)
/// and common bait phrases. Pure heuristic — emphasis and excitement also
/// use caps, so this is a *signal*, not a verdict.
pub fn count_outrage_signals(text: &str) -> u32 {
    const BAIT_PHRASES: &[&str] = &[
        "you won't believe",
        "shocking",
        "outrageous",
        "breaking:",
        "everyone is talking",
    ];
    let mut count: u32 = 0;
    for raw in text.split_whitespace() {
        let w: String = raw
            .trim_matches(|c: char| !c.is_alphanumeric())
            .chars()
            .collect();
        let alpha: String = w.chars().filter(|c| c.is_alphabetic()).collect();
        if alpha.len() >= 3 && alpha.chars().all(|c| c.is_uppercase()) {
            count += 1;
        }
    }
    let lower = text.to_lowercase();
    for phrase in BAIT_PHRASES {
        if lower.contains(phrase) {
            count += 1;
        }
    }
    count
}

/// Health metrics for a two-party conversation.
///
/// The connection-first idea: a balanced, substantive back-and-forth between
/// two people scores higher than one-sided bursts, because it looks more
/// like two humans actually talking.
#[derive(Debug, Clone, Copy)]
pub struct ConversationHealth {
    /// 0.0..=1.0. 1.0 means both sides sent the same number of messages;
    /// 0.0 means one side sent everything (or nobody sent anything).
    pub turn_balance: f32,
    /// Fraction of all messages containing a question, 0.0..=1.0.
    /// Questions invite replies, which is the unit of connection.
    pub question_rate: f32,
    /// Average words per message across both sides. Longer turns usually
    /// carry more substance than rapid one-liners.
    pub depth_score: f32,
}

/// Compute conversation health from each side's messages.
///
/// `a_msgs` and `b_msgs` are the two participants' message texts. Pure
/// function over on-device message history.
pub fn conversation_health(a_msgs: &[&str], b_msgs: &[&str]) -> ConversationHealth {
    let total = (a_msgs.len() + b_msgs.len()) as f32;
    let turn_balance = if total == 0.0 {
        0.0
    } else {
        let diff = (a_msgs.len() as f32 - b_msgs.len() as f32).abs();
        1.0 - diff / total
    };
    let mut questions: u32 = 0;
    let mut words: u32 = 0;
    for m in a_msgs.iter().chain(b_msgs.iter()) {
        if m.contains('?') {
            questions += 1;
        }
        words += TextSignals::analyze(m).word_count;
    }
    let question_rate = if total == 0.0 {
        0.0
    } else {
        questions as f32 / total
    };
    let depth_score = if total == 0.0 {
        0.0
    } else {
        words as f32 / total
    };
    ConversationHealth {
        turn_balance,
        question_rate,
        depth_score,
    }
}

/// A feed item to be ranked for connection value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedItem {
    /// Stable item identifier.
    pub id: String,
    /// Visible text preview of the item.
    pub preview: String,
    /// True when the author and the viewer mutually follow each other.
    /// Per the sharing rule, mutual follows are the trusted social graph.
    pub from_mutual_follow: bool,
    /// True when the item cites its source.
    pub has_cited_source: bool,
    /// Detected outrage-bait signals (see [`count_outrage_signals`]).
    /// Supplied by the caller; this module does not fetch or judge content.
    pub outrage_flags: u32,
}

impl FeedItem {
    /// Build a feed item. Handles are trimmed; `preview` is kept as-is.
    pub fn new(
        id: &str,
        preview: &str,
        from_mutual_follow: bool,
        has_cited_source: bool,
        outrage_flags: u32,
    ) -> Self {
        FeedItem {
            id: id.trim().to_string(),
            preview: preview.to_string(),
            from_mutual_follow,
            has_cited_source,
            outrage_flags,
        }
    }
}

/// Rank a feed item for connection value (higher = rank first).
///
/// Philosophy, stated plainly so it can be argued with:
/// - Reward what connection looks like: mutual follows, cited sources,
///   questions that invite a reply, and threads where both sides actually
///   talk (see [`ConversationHealth`]).
/// - Penalize what doomscrolling looks like: outrage bait and rapid,
///   shallow items.
/// - This orders the feed; it never hides or removes anything. The viewer
///   can always scroll past the ranking.
///
/// Scoring (all on-device, all transparent):
/// - base 10
/// - +25 mutual follow, +15 cited source, +10 if the preview asks a question
/// - +turn_balance * 10 (balanced threads win) and +depth_score capped at 10
/// - -10 per outrage flag, -10 if the preview is under 5 words (shallow)
/// - floored at 0
pub fn connection_score(item: &FeedItem, health: &ConversationHealth) -> u32 {
    let signals = TextSignals::analyze(&item.preview);
    let mut score: i32 = 10;
    if item.from_mutual_follow {
        score += 25;
    }
    if item.has_cited_source {
        score += 15;
    }
    if signals.question_count > 0 {
        score += 10;
    }
    score += (health.turn_balance * 10.0).round() as i32;
    score += health.depth_score.min(10.0).round() as i32;
    score -= (item.outrage_flags as i32) * 10;
    if signals.word_count < 5 {
        score -= 10;
    }
    score.max(0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-4
    }

    #[test]
    fn signals_basic() {
        let s = TextSignals::analyze("Hello world");
        assert_eq!(s.word_count, 2);
        assert!(approx(s.unique_word_ratio, 1.0));
        assert_eq!(s.question_count, 0);
        assert_eq!(s.exclamation_count, 0);
        assert!(approx(s.avg_word_len, 5.0));
    }

    #[test]
    fn signals_punctuation_and_repetition() {
        let s = TextSignals::analyze("Really? Yes! Really?");
        assert_eq!(s.word_count, 3);
        // {really, yes} -> 2/3
        assert!(approx(s.unique_word_ratio, 2.0 / 3.0));
        assert_eq!(s.question_count, 2);
        assert_eq!(s.exclamation_count, 1);
        assert!(approx(s.avg_word_len, 5.0)); // (6+3+6)/3
    }

    #[test]
    fn signals_empty() {
        let s = TextSignals::analyze("");
        assert_eq!(s.word_count, 0);
        assert!(approx(s.unique_word_ratio, 0.0));
        assert!(approx(s.avg_word_len, 0.0));
        assert_eq!(s.question_count, 0);
        assert_eq!(s.exclamation_count, 0);
    }

    #[test]
    fn sentiment_positive() {
        assert!(sentiment_heuristic("I love this wonderful beautiful day") > 0);
    }

    #[test]
    fn sentiment_negative() {
        assert!(sentiment_heuristic("I hate this terrible awful scam") < 0);
    }

    #[test]
    fn sentiment_neutral() {
        assert_eq!(sentiment_heuristic("The meeting is at noon tomorrow"), 0);
    }

    #[test]
    fn sentiment_clamped() {
        let very_happy = "love ".repeat(50);
        assert_eq!(sentiment_heuristic(&very_happy), 100);
        let very_angry = "hate ".repeat(50);
        assert_eq!(sentiment_heuristic(&very_angry), -100);
    }

    #[test]
    fn turn_balance_equal() {
        let h = conversation_health(&["a", "b", "c"], &["d", "e", "f"]);
        assert!(approx(h.turn_balance, 1.0));
    }

    #[test]
    fn turn_balance_one_sided() {
        let h = conversation_health(&["a", "b", "c", "d"], &[]);
        assert!(approx(h.turn_balance, 0.0));
    }

    #[test]
    fn turn_balance_empty() {
        let h = conversation_health(&[], &[]);
        assert!(approx(h.turn_balance, 0.0));
        assert!(approx(h.question_rate, 0.0));
        assert!(approx(h.depth_score, 0.0));
    }

    #[test]
    fn question_rate_and_depth() {
        let h = conversation_health(
            &["How are you?", "I am well thanks"],
            &["What did you think of the game?", "ok"],
        );
        assert!(approx(h.question_rate, 0.5)); // 2 of 4
        // words: 3 + 4 + 7 + 1 = 15 over 4 messages
        assert!(approx(h.depth_score, 15.0 / 4.0));
    }

    #[test]
    fn outrage_signals_detected() {
        assert!(count_outrage_signals("THIS is TERRIBLE and OUTRAGEOUS!!!") > 0);
        assert_eq!(count_outrage_signals("A calm note about the garden."), 0);
    }

    #[test]
    fn feed_prefers_connection_over_doomscroll() {
        // A substantive, mutual, cited conversation starter with a healthy thread.
        let good = FeedItem::new(
            "good",
            "What did you learn from the gateway session today? I found the focus exercises surprisingly grounding.",
            true,  // mutual follow
            true,  // cited source
            0,     // no outrage flags
        );
        let good_health = conversation_health(
            &["What did you learn?", "The focus exercises helped me settle"],
            &["Same here, session three was deep", "Want to compare notes tomorrow?"],
        );
        // A shallow viral outrage item: no mutual follow, no source, short, bait.
        let bad = FeedItem::new(
            "bad",
            "SHOCKING!!! You won't believe this!!!",
            false,
            false,
            4,
        );
        let bad_health = conversation_health(&["wow", "crazy"], &[]);
        assert!(connection_score(&good, &good_health) > connection_score(&bad, &bad_health));
    }

    #[test]
    fn feed_score_never_negative() {
        let item = FeedItem::new("x", "hi", false, false, 99);
        let health = conversation_health(&[], &[]);
        assert_eq!(connection_score(&item, &health), 0);
    }

    #[test]
    fn feed_rewards_questions_and_citations() {
        let plain = FeedItem::new("p", "Here is a fairly long and thoughtful statement about the day.", false, false, 0);
        let cited = FeedItem::new("c", "Here is a fairly long and thoughtful statement about the day?", false, true, 0);
        let health = conversation_health(&["a"], &["b"]);
        assert!(connection_score(&cited, &health) > connection_score(&plain, &health));
    }
}
