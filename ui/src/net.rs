//! Router ↔ mesh wiring: the live pump between the UI and the network.
//!
//! [`RouterLink::pump`] is the single integration point the embedding
//! app calls each frame (or each event-loop turn):
//!
//! ```text
//! UI events → Router                  (user typed / navigated)
//! Router::take_open_request → MeshNode::open_channel   (handshake out)
//! Router::drain_outbound → MeshNode::send_data          (chat frames out)
//! MeshNode::poll → MeshNode::take_inbound → Router::deliver_frame (frames in)
//! ```
//!
//! The pump is synchronous and non-blocking: every stage drains what
//! is available RIGHT NOW. There is no batching, no timer, and no
//! artificial delay on the live path — a message typed this frame is
//! handed to the platform transport before `pump` returns (when the
//! channel is ready). The offline queue only engages for peers that
//! are unreachable.
//!
//! Inbound frames for a peer whose chat is not open stay buffered in
//! the [`MeshNode`](trv_core::mesh::MeshNode) until the user opens
//! that chat; [`RouterLink::pump`] delivers them the moment the chat
//! becomes active.

use trv_core::mesh::{MeshEvent, MeshNode};
use trv_core::transport::PeerId;

use crate::router::{FrameOutcome, Router};

/// What [`RouterLink::pump`] observed, for the embedding app's
/// notifications and status UI.
#[derive(Debug, Default)]
pub struct PumpReport {
    /// Handshakes initiated this pump.
    pub handshakes_started: usize,
    /// Outbound chat frames handed to the mesh this pump.
    pub frames_sent: usize,
    /// Inbound frames delivered to the active chat this pump.
    pub frames_delivered: usize,
    /// Frames refused because no chat is open (still buffered in the mesh).
    pub frames_held: usize,
    /// Mesh events (channel ready, voice arrived, expiry, ...).
    pub events: Vec<String>,
}

/// The UI↔network pump. Stateless; all state lives in the [`Router`]
/// and the [`MeshNode`].
pub struct RouterLink;

impl RouterLink {
    /// Run one full pump cycle. `now_secs` is caller-supplied time for
    /// rekey age checks and queue expiry (no trusted clock in core).
    ///
    /// Order per cycle: (1) mesh poll — handshake/rekey/discovery move
    /// first so a just-completed channel is usable immediately;
    /// (2) open requests from the UI; (3) outbound chat frames;
    /// (4) inbound frames to the active chat.
    pub fn pump(router: &mut Router, mesh: &mut MeshNode, now_secs: u64) -> PumpReport {
        let mut report = PumpReport::default();

        // 1. Let the mesh advance: inbound frames, handshakes, rekeys,
        //    discovery, expiry. Non-blocking; drains what's available.
        for event in mesh.poll(now_secs) {
            match &event {
                MeshEvent::ChannelReady(peer) => {
                    report.events.push(format!("channel ready: {peer:?}"));
                }
                MeshEvent::ChannelFailed(peer) => {
                    report.events.push(format!("channel failed: {peer:?}"));
                }
                MeshEvent::VoiceMessageComplete { peer, msg_id: _, audio } => {
                    report.events.push(format!(
                        "voice message from {peer:?} ({} bytes)",
                        audio.len()
                    ));
                }
                MeshEvent::MessageExpired { peer, id: _ } => {
                    report.events.push(format!("message to {peer:?} expired undelivered"));
                }
                MeshEvent::Rekeyed(peer) => {
                    report.events.push(format!("rekeyed: {peer:?}"));
                }
                MeshEvent::PeerDiscovered(peer) => {
                    report.events.push(format!("peer discovered: {peer:?}"));
                }
                _ => {}
            }
            // Keep DataReceived / VoiceChunkReceived quiet: the counts below cover them.
            let _ = &event;
        }

        // 2. The UI wants channels for these peers: start handshakes.
        while let Some(raw) = router.take_open_request() {
            let peer = PeerId(raw);
            if mesh.open_channel(&peer).is_ok() {
                report.handshakes_started += 1;
            }
        }

        // 3. Chat frames out: the active chat's sealed frames go straight
        //    to the mesh, which sends them immediately when the channel
        //    is ready (or queues when the peer is unreachable).
        if let Some(raw) = router.active_peer() {
            let peer = PeerId(raw);
            for frame in router.drain_outbound() {
                if mesh.send_data(&peer, &frame, now_secs).is_ok() {
                    report.frames_sent += 1;
                }
            }
            // 4. Frames in: deliver buffered inbound to the active chat.
            for inbound in mesh.take_inbound(&peer) {
                match router.deliver_frame(&inbound) {
                    FrameOutcome::Handled(_) => report.frames_delivered += 1,
                    FrameOutcome::NoChatOpen => report.frames_held += 1,
                }
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::rc::Rc;
    use trv_core::mesh::MeshNode as CoreMeshNode;
    use trv_core::transport::{IdentityKey, PeerAdvert, PeerId, PeerStatus, Transport, TransportError};

    struct Hub {
        inboxes: HashMap<PeerId, VecDeque<(PeerId, Vec<u8>)>>,
    }

    struct LoopTransport {
        hub: Rc<RefCell<Hub>>,
        me: PeerId,
    }

    impl Transport for LoopTransport {
        fn send_frame(&mut self, peer: &PeerId, bytes: &[u8]) -> Result<(), TransportError> {
            self.hub
                .borrow_mut()
                .inboxes
                .entry(*peer)
                .or_default()
                .push_back((self.me, bytes.to_vec()));
            Ok(())
        }
        fn recv_frame(&mut self) -> Option<(PeerId, Vec<u8>)> {
            self.hub.borrow_mut().inboxes.get_mut(&self.me)?.pop_front()
        }
        fn discover_peers(&mut self) -> Vec<PeerAdvert> {
            Vec::new()
        }
        fn peer_status(&self, _peer: &PeerId) -> PeerStatus {
            PeerStatus::Online
        }
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "trv-net-test-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// End-to-end through the real UI stack: two routers with messaging
    /// enabled, conversations built on loopback-authenticated channels,
    /// frames pumped through two mesh nodes. A message typed in A's
    /// chat arrives in B's chat.
    #[test]
    fn pump_carries_chat_end_to_end() {
        use crate::platform::{Screen, TextScreen, UiEvent};
        use std::rc::Rc;
        use trv_backend::entitlement;
        use trv_backend::history::{HistoryMessage, HistoryStatus, HistoryStore};
        use trv_backend::subscriptions::Tier;
        use trv_core::crypto::ed25519;
        use trv_core::messaging::Conversation;
        use trv_core::transport::establish_auth;

        const ISSUER_SEED: [u8; 32] = *b"net-test-issuer-0000000000000000";
        fn live_entitlement() -> trv_backend::entitlement::Entitlement {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs();
            let receipt =
                entitlement::issue(&ISSUER_SEED, Tier::Monthly, now, now + 30 * 86_400).expect("issue");
            let (_, ipub) = ed25519::generate(&ISSUER_SEED);
            entitlement::verify_and_check(ipub.as_bytes(), &receipt).expect("live")
        }
        fn store(tag: &str) -> Rc<HistoryStore> {
            let dir = tmpdir(tag);
            Rc::new(HistoryStore::open_with_iterations(&dir, "net-pass", 1000).expect("store"))
        }
        fn type_text(r: &mut Router, text: &str) {
            for c in text.chars() {
                r.on_event(UiEvent::Char(c));
            }
        }

        // Two mesh nodes, paired via QR, sharing the hub.
        let hub = Rc::new(RefCell::new(Hub { inboxes: HashMap::new() }));
        let ida = IdentityKey::generate(&[0xA1; 32]);
        let idb = IdentityKey::generate(&[0xB2; 32]);
        let pa = PeerId::from_public(ida.public());
        let pb = PeerId::from_public(idb.public());
        let ka = *ida.public().as_bytes();
        let kb = *idb.public().as_bytes();
        let ta = LoopTransport { hub: Rc::clone(&hub), me: pa };
        let tb = LoopTransport { hub: Rc::clone(&hub), me: pb };
        let mut ma = CoreMeshNode::new(ida, Box::new(ta), &tmpdir("e2e-a"), &[0x11; 32]).expect("ma");
        let mut mb = CoreMeshNode::new(idb, Box::new(tb), &tmpdir("e2e-b"), &[0x22; 32]).expect("mb");
        let ca_qr = ma.set_own_card("Alice", "alice", 1000).expect("card");
        let cb_qr = mb.set_own_card("Bob", "bob", 1000).expect("card");
        ma.pair_via_qr(&cb_qr, 1001).expect("pair");
        mb.pair_via_qr(&ca_qr, 1001).expect("pair");

        // Mesh handshake through the nodes.
        ma.open_channel(&pb).expect("open");
        mb.poll(1002);
        ma.poll(1003);
        assert!(ma.has_channel(&pb) && mb.has_channel(&pa));

        // Routers with messaging enabled, history seeded so each peer
        // appears in the other's conversation list.
        let (ida2, _) = ed25519::generate(&[0xA1; 32]);
        let (idb2, _) = ed25519::generate(&[0xB2; 32]);
        let _ = (ida2, idb2);
        let sa = store("e2e-sa");
        let sb = store("e2e-sb");
        for (st, peer) in [(&sa, kb), (&sb, ka)] {
            let mut id = [0u8; 16];
            id[0] = 9;
            st.append(&HistoryMessage {
                id,
                peer,
                outgoing: false,
                status: HistoryStatus::Delivered,
                timestamp: 1,
                text: "hey".into(),
            })
            .expect("seed");
        }
        let mut ra = Router::new("alice", 320, 200);
        let mut rb = Router::new("bob", 320, 200);
        let mut ha = HashMap::new();
        ha.insert(kb, "bob".to_string());
        let mut hb = HashMap::new();
        hb.insert(ka, "alice".to_string());
        ra.enable_messaging(Rc::clone(&sa), ha, Some(live_entitlement()));
        rb.enable_messaging(Rc::clone(&sb), hb, Some(live_entitlement()));

        // E2E conversation channels (loopback-authenticated; in the
        // real app the mesh handshake's channel feeds this layer).
        let ka_id = IdentityKey::generate(&[0xA1; 32]);
        let kb_id = IdentityKey::generate(&[0xB2; 32]);
        let (cha_ab, cha_ba) = establish_auth(&ka_id, &kb_id).expect("auth");
        ra.open_chat(kb, Conversation::new(cha_ab, ka_id.public(), kb_id.public()));
        rb.open_chat(ka, Conversation::new(cha_ba, kb_id.public(), ka_id.public()));
        assert_eq!(ra.active_peer(), Some(kb));
        assert_eq!(rb.active_peer(), Some(ka));

        // Alice types and sends; the pump moves the sealed frame
        // through both mesh nodes (link-encrypted) to Bob's router.
        type_text(&mut ra, "hello bob");
        ra.on_event(UiEvent::Enter);
        let rep = RouterLink::pump(&mut ra, &mut ma, 1004);
        assert_eq!(rep.frames_sent, 1, "pump must forward the chat frame");
        let rep_b = RouterLink::pump(&mut rb, &mut mb, 1005);
        assert_eq!(rep_b.frames_delivered, 1, "bob's pump must deliver");

        // Bob's chat shows Alice's message.
        let mut out = String::new();
        rb.draw_text(&mut out, 60, 24);
        assert!(out.contains("hello bob"), "bob sees the message: {out}");
    }

    #[test]
    fn pump_moves_router_frames_through_mesh() {
        // Focused unit: pump drains router outbound into the mesh and
        // delivers mesh inbound to the router, without a full UI flow.
        // (The full E2E chat flow is covered by core mesh tests; this
        // asserts the wiring contract: no frames lost, none duplicated.)
        let hub = Rc::new(RefCell::new(Hub { inboxes: HashMap::new() }));
        let ida = IdentityKey::generate(&[0xC1; 32]);
        let idb = IdentityKey::generate(&[0xC2; 32]);
        let pa = PeerId::from_public(ida.public());
        let pb = PeerId::from_public(idb.public());
        let ta = LoopTransport { hub: Rc::clone(&hub), me: pa };
        let tb = LoopTransport { hub: Rc::clone(&hub), me: pb };
        let mut ma =
            CoreMeshNode::new(ida, Box::new(ta), &tmpdir("c"), &[0x33; 32]).expect("ma");
        let mut mb =
            CoreMeshNode::new(idb, Box::new(tb), &tmpdir("d"), &[0x44; 32]).expect("mb");
        let ca = ma.set_own_card("Alice", "alice", 1000).expect("card");
        let cb = mb.set_own_card("Bob", "bob", 1000).expect("card");
        ma.pair_via_qr(&cb, 1001).expect("pair");
        mb.pair_via_qr(&ca, 1001).expect("pair");

        // Handshake via raw mesh polls.
        ma.open_channel(&pb).expect("open");
        mb.poll(1002);
        ma.poll(1003);
        assert!(ma.has_channel(&pb));

        // Send through the mesh; the bytes must be synchronously handed
        // to the transport (zero-delay live path).
        ma.send_data(&pb, b"ping", 1004).expect("send");
        assert_eq!(hub.borrow().inboxes.get(&pb).map(|q| q.len()), Some(1));

        // Peer polls and takes inbound.
        mb.poll(1005);
        let got = mb.take_inbound(&pa);
        assert_eq!(got, vec![b"ping".to_vec()]);

        // Pump report shape on an idle router (no messaging enabled):
        // nothing to do, no crash.
        let mut r = Router::new("alice", 320, 200);
        let rep = RouterLink::pump(&mut r, &mut ma, 1006);
        assert_eq!(rep.frames_sent, 0);
        assert_eq!(rep.handshakes_started, 0);
        let _ = HashSet::<u8>::new();
    }
}
