//! Threat entities: the adversaries the player defends against.
//!
//! Each threat kind maps to a REAL threat-awareness lesson (the game's
//! educational purpose). Behaviors describe how the threat acts in the
//! simulation so the platform layer can animate it faithfully.

/// Unique identifier for a threat instance within a mission.
pub type ThreatId = u32;

/// The kinds of threats in God's Eye. Each teaches a real lesson.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatKind {
    /// A deceptive message trying to steal credentials.
    /// Lesson: verify the sender, never click blind links.
    Phishing,
    /// Malware spreading laterally through the network.
    /// Lesson: patch promptly, segment networks.
    Worm,
    /// A compromised vendor update carrying a payload.
    /// Lesson: trust but verify the supply chain.
    SupplyChain,
    /// Ransomware encrypting critical systems, demanding payment.
    /// Lesson: backups are the only real defense; never pay.
    Ransomware,
    /// An insider abusing legitimate access.
    /// Lesson: least privilege, audit trails.
    Insider,
    /// A flood of traffic trying to knock services offline.
    /// Lesson: rate limiting, upstream filtering.
    DDoS,
    /// A fake persona manipulating a target into leaking secrets.
    /// Lesson: verify identity out-of-band before sharing.
    SocialEngineering,
}

impl ThreatKind {
    /// The lesson the player should take away.
    pub fn lesson(self) -> &'static str {
        match self {
            ThreatKind::Phishing => "Verify the sender. Never click blind links.",
            ThreatKind::Worm => "Patch promptly. Segment your networks.",
            ThreatKind::SupplyChain => "Trust the supply chain only after verification.",
            ThreatKind::Ransomware => "Keep offline backups. Never pay the ransom.",
            ThreatKind::Insider => "Least privilege. Audit everything.",
            ThreatKind::DDoS => "Rate-limit at the edge. Filter upstream.",
            ThreatKind::SocialEngineering => "Verify identity out-of-band before sharing secrets.",
        }
    }

    /// Base severity: how much damage per second while uncontained.
    pub fn base_damage_per_sec(self) -> u32 {
        match self {
            ThreatKind::Phishing => 2,
            ThreatKind::Worm => 5,
            ThreatKind::SupplyChain => 8,
            ThreatKind::Ransomware => 10,
            ThreatKind::Insider => 7,
            ThreatKind::DDoS => 6,
            ThreatKind::SocialEngineering => 3,
        }
    }
}

/// How a threat behaves once active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatBehavior {
    /// Sits quiet, then strikes (phishing, insider).
    Dormant,
    /// Spreads to adjacent nodes over time (worm).
    Spreading,
    /// Damage ramps up the longer it is uncontained (ransomware, DDoS).
    Escalating,
    /// Moves between nodes to avoid containment (supply chain).
    Elusive,
}

/// Lifecycle of a single threat instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatStatus {
    /// Spawned but not yet visible to the player.
    Hidden,
    /// Visible; the player can respond.
    Active,
    /// Player contained it. No more damage.
    Contained,
    /// It ran its course uncontained. Damage done.
    Escalated,
}

/// A single threat instance in a mission.
#[derive(Debug, Clone)]
pub struct Threat {
    pub id: ThreatId,
    pub kind: ThreatKind,
    pub behavior: ThreatBehavior,
    pub status: ThreatStatus,
    /// Seconds since becoming active.
    pub active_secs: u64,
}

impl Threat {
    pub fn new(id: ThreatId, kind: ThreatKind) -> Self {
        let behavior = match kind {
            ThreatKind::Phishing | ThreatKind::Insider => ThreatBehavior::Dormant,
            ThreatKind::Worm => ThreatBehavior::Spreading,
            ThreatKind::Ransomware | ThreatKind::DDoS => ThreatBehavior::Escalating,
            ThreatKind::SupplyChain => ThreatBehavior::Elusive,
            ThreatKind::SocialEngineering => ThreatBehavior::Dormant,
        };
        Threat {
            id,
            kind,
            behavior,
            status: ThreatStatus::Hidden,
            active_secs: 0,
        }
    }

    /// Reveal the threat to the player.
    pub fn reveal(&mut self) {
        if self.status == ThreatStatus::Hidden {
            self.status = ThreatStatus::Active;
        }
    }

    /// The player contains the threat. Only active threats can be contained.
    pub fn contain(&mut self) -> bool {
        if self.status == ThreatStatus::Active {
            self.status = ThreatStatus::Contained;
            true
        } else {
            false
        }
    }

    /// Advance one second. Returns the damage dealt this second.
    /// Uncontained active threats escalate past their response window.
    pub fn tick(&mut self, response_window_secs: u64) -> u32 {
        if self.status != ThreatStatus::Active {
            return 0;
        }
        self.active_secs = self.active_secs.saturating_add(1);
        if self.active_secs > response_window_secs {
            self.status = ThreatStatus::Escalated;
        }
        let mut dmg = self.kind.base_damage_per_sec();
        if matches!(self.behavior, ThreatBehavior::Escalating) {
            // Escalating threats ramp damage as the response window closes:
            // up to 5x by the final quarter. The pressure is the lesson.
            let quarter = response_window_secs.max(4) / 4;
            let quarters = (self.active_secs / quarter.max(1)).min(4);
            dmg = dmg.saturating_mul(1 + quarters as u32);
        }
        dmg
    }

    pub fn is_live(&self) -> bool {
        matches!(self.status, ThreatStatus::Active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contain_only_when_active() {
        let mut t = Threat::new(1, ThreatKind::Phishing);
        assert!(!t.contain()); // hidden: no
        t.reveal();
        assert!(t.contain()); // active: yes
        assert!(!t.contain()); // contained: no
    }

    #[test]
    fn uncontained_threat_escalates() {
        let mut t = Threat::new(2, ThreatKind::Worm);
        t.reveal();
        // Window is 10s; tick 11 times.
        for _ in 0..10 {
            t.tick(10);
            assert_eq!(t.status, ThreatStatus::Active);
        }
        t.tick(10);
        assert_eq!(t.status, ThreatStatus::Escalated);
        // Escalated threats deal no further damage (they're spent).
        assert_eq!(t.tick(10), 0);
    }

    #[test]
    fn contained_threat_deals_no_damage() {
        let mut t = Threat::new(3, ThreatKind::Ransomware);
        t.reveal();
        t.contain();
        assert_eq!(t.tick(10), 0);
    }

    #[test]
    fn every_kind_has_a_lesson() {
        for kind in [
            ThreatKind::Phishing,
            ThreatKind::Worm,
            ThreatKind::SupplyChain,
            ThreatKind::Ransomware,
            ThreatKind::Insider,
            ThreatKind::DDoS,
            ThreatKind::SocialEngineering,
        ] {
            assert!(!kind.lesson().is_empty());
            assert!(kind.base_damage_per_sec() > 0);
        }
    }

    #[test]
    fn escalating_threat_ramps_damage() {
        // Window 20s -> quarters of 5s. Damage must strictly increase
        // across quarters while the threat is still active.
        let mut t = Threat::new(4, ThreatKind::Ransomware);
        t.reveal();
        let d_early = t.tick(20); // active_secs=1, quarter 0 -> 1x
        for _ in 0..5 {
            t.tick(20);
        }
        let d_mid = t.tick(20); // active_secs=7, quarter 1 -> 2x
        for _ in 0..5 {
            t.tick(20);
        }
        let d_late = t.tick(20); // active_secs=13, quarter 2 -> 3x
        assert!(d_mid > d_early, "damage must ramp: {d_mid} > {d_early}");
        assert!(d_late > d_mid, "damage must ramp: {d_late} > {d_mid}");
        assert_eq!(t.status, ThreatStatus::Active); // still containable
    }
}
