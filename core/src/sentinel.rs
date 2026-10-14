//! The Sentinel — the ONE Enhanced Intelligence of The Remote Viewer.
//!
//! Voice-first (Siri/Google equivalent): the viewer speaks to their
//! Sentinel; it learns exclusively about them, on-device only.
//!
//! Research rule: only NOT researched if NOT PUBLIC AND NOT ABOUT ME.
//! Declassified-only: global-net search is permitted for declassified
//! requests (We The People / 1st Amendment / FOIA).

use crate::moe::route;

/// The Sentinel, bound to one device owner.
#[derive(Debug)]
pub struct Sentinel {
    owner_handle: String,
}

impl Sentinel {
    /// Bind a Sentinel to the device owner. Fully local.
    pub fn new(owner_handle: &str) -> Self {
        Sentinel {
            owner_handle: owner_handle.to_string(),
        }
    }

    /// The handle of the owner this Sentinel is bound to.
    pub fn owner(&self) -> &str {
        &self.owner_handle
    }

    /// Answer a spoken request.
    ///
    /// Today this routes the request through the on-device MoE gate
    /// and reports which local expert skill would handle it. Real
    /// on-device inference keeps this same API and replaces the
    /// routing note with a generated answer. Never the network.
    pub fn ask(&self, request: &str) -> String {
        let skill = route(request);
        format!(
            "Sentinel for {} (on-device): routing to the {} expert.",
            self.owner_handle,
            skill.name()
        )
    }

    /// Research gate: research proceeds unless the topic is BOTH
    /// not-public AND not-about-the-owner.
    ///
    /// Pure predicate — no I/O, no network.
    pub fn may_research(is_public: bool, is_about_owner: bool) -> bool {
        is_public || is_about_owner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_binds_owner_and_ask_references_them() {
        let sentinel = Sentinel::new("test-viewer");
        let reply = sentinel.ask("what did I learn today?");
        assert!(reply.contains("test-viewer"));
        assert!(reply.contains("on-device"));
    }

    #[test]
    fn ask_routes_through_local_moe() {
        let sentinel = Sentinel::new("viewer");
        assert!(sentinel.ask("how do I do CPR?").contains("first-aid"));
        assert!(sentinel.ask("explain qubit superposition").contains("quantum"));
        assert!(sentinel.ask("hello").contains("coordinator"));
    }

    #[test]
    fn each_sentinel_serves_its_own_owner_only() {
        let alice = Sentinel::new("alice");
        let bob = Sentinel::new("bob");
        assert!(alice.ask("hello").contains("alice"));
        assert!(bob.ask("hello").contains("bob"));
        assert!(!bob.ask("hello").contains("alice"));
    }

    #[test]
    fn owner_returns_the_bound_handle_directly() {
        let sentinel = Sentinel::new("test-viewer");
        assert_eq!(sentinel.owner(), "test-viewer");
        // Binding is per-instance: a second Sentinel keeps its own owner.
        let other = Sentinel::new("other-viewer");
        assert_eq!(other.owner(), "other-viewer");
        assert_ne!(sentinel.owner(), other.owner());
    }

    #[test]
    fn may_research_allows_public_or_owner_topics() {
        assert!(Sentinel::may_research(true, true));
        assert!(Sentinel::may_research(true, false));
        assert!(Sentinel::may_research(false, true));
    }

    #[test]
    fn may_research_denies_only_nonpublic_nonowner_topics() {
        // The research rule: NOT researched if NOT PUBLIC AND NOT ABOUT ME.
        assert!(!Sentinel::may_research(false, false));
    }
}
