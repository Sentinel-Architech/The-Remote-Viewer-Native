
#[cfg(test)]
mod tests {
    use crate::mesh::{
        IdentityKey, InitiatorHandshake, LinkKind, MeshError, MeshEvent, MeshNode, OnionPacket,
        PeerAdvert, PeerId, PeerStatus, PublicKey, RelayAction, RelayHop, Transport,
        VoiceChunk, decode_link, encode_link, relay_open, MAX_LINK_FRAME, MAX_ONION_MESSAGE,
        MAX_VOICE_CHUNK, REKEY_BLOB_LEN,
    };
    use crate::transport as transport;
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::path::PathBuf;
    use std::rc::Rc;

    // ---------- test transport: in-memory hub ----------

    struct Hub {
        inboxes: HashMap<PeerId, VecDeque<(PeerId, Vec<u8>)>>,
        adverts: Vec<Vec<u8>>,
        online: HashSet<PeerId>,
    }

    struct MemoryTransport {
        hub: Rc<RefCell<Hub>>,
        me: PeerId,
        send_fails: bool,
    }

    impl Transport for MemoryTransport {
        fn send_frame(&mut self, peer: &PeerId, bytes: &[u8]) -> Result<(), transport::TransportError> {
            if self.send_fails {
                return Err(transport::TransportError::SendFailed);
            }
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
            self.hub
                .borrow()
                .adverts
                .iter()
                .filter_map(|b| PeerAdvert::from_bytes(b).ok())
                .filter(|a| a.peer_id() != self.me)
                .collect()
        }

        fn peer_status(&self, peer: &PeerId) -> PeerStatus {
            if self.hub.borrow().online.contains(peer) {
                PeerStatus::Online
            } else {
                PeerStatus::Unknown
            }
        }
    }

    fn test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trv-mesh-test-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn identity(seed: u8) -> IdentityKey {
        IdentityKey::generate(&[seed; 32])
    }

    /// Two paired nodes sharing a hub. Returns (node_a, node_b, hub, id_a, id_b).
    fn paired_nodes(tag: &str) -> (MeshNode, MeshNode, Rc<RefCell<Hub>>, PeerId, PeerId) {
        let hub = Rc::new(RefCell::new(Hub {
            inboxes: HashMap::new(),
            adverts: Vec::new(),
            online: HashSet::new(),
        }));
        let ida = identity(0xA1);
        let idb = identity(0xB2);
        let pa = PeerId::from_public(ida.public());
        let pb = PeerId::from_public(idb.public());
        hub.borrow_mut().online.insert(pa);
        hub.borrow_mut().online.insert(pb);
        let ta = MemoryTransport { hub: Rc::clone(&hub), me: pa, send_fails: false };
        let tb = MemoryTransport { hub: Rc::clone(&hub), me: pb, send_fails: false };
        let mut a = MeshNode::new(ida, Box::new(ta), &test_dir(&format!("{tag}-a")), &[0x11; 32]).expect("node a");
        let mut b = MeshNode::new(idb, Box::new(tb), &test_dir(&format!("{tag}-b")), &[0x22; 32]).expect("node b");
        // QR pairing both ways.
        let card_a = a.set_own_card("Alice", "alice", 1000).expect("card a");
        let card_b = b.set_own_card("Bob", "bob", 1000).expect("card b");
        assert_eq!(a.pair_via_qr(&card_b, 1001).expect("pair"), pb);
        assert_eq!(b.pair_via_qr(&card_a, 1001).expect("pair"), pa);
        (a, b, hub, pa, pb)
    }

    /// Drive a full handshake between two paired nodes.
    fn handshake(a: &mut MeshNode, b: &mut MeshNode, pb: &PeerId, now: u64) {
        a.open_channel(pb).expect("open");
        let ev_b: Vec<String> = b.poll(now).iter().map(|e| format!("{e:?}")).collect();
        assert!(ev_b.iter().any(|e| e.contains("ChannelReady")), "b ready: {ev_b:?}");
        let ev_a: Vec<String> = a.poll(now).iter().map(|e| format!("{e:?}")).collect();
        assert!(ev_a.iter().any(|e| e.contains("ChannelReady")), "a ready: {ev_a:?}");
    }

    // ---------- handshake ----------

    #[test]
    fn handshake_round_trip_over_memory_transport() {
        let (mut a, mut b, _hub, pa, pb) = paired_nodes("hs");
        handshake(&mut a, &mut b, &pb, 1000);
        assert!(a.has_channel(&pb));
        assert!(b.has_channel(&pa));
    }

    #[test]
    fn tampered_hello_is_rejected_silently() {
        let (mut a, mut b, hub, _pa, pb) = paired_nodes("tamper");
        // Manually send a corrupted hello: build a valid one, flip a byte.
        a.open_channel(&pb).expect("open");
        {
            let mut h = hub.borrow_mut();
            let q = h.inboxes.get_mut(&pb).expect("hello queued");
            let (from, mut bytes) = q.pop_front().expect("hello");
            bytes[20] ^= 0x01; // corrupt inside the auth blob
            q.push_front((from, bytes));
        }
        let events = b.poll(1000);
        assert!(!b.has_channel(&a.own_id()));
        assert!(events.iter().all(|e| !format!("{e:?}").contains("ChannelReady")));
    }

    #[test]
    fn hello_from_stranger_is_ignored() {
        let (a, mut b, hub, pa, pb) = paired_nodes("stranger");
        // Eve is not a contact of b.
        let ide = identity(0xE5);
        let pe = PeerId::from_public(ide.public());
        let hs = InitiatorHandshake::new().unwrap();
        // Eve crafts a hello naming b as recipient, signed by Eve.
        let hello = hs.hello_auth(&ide, &PublicKey::from_bytes(pb.0));
        let frame = encode_link(LinkKind::HandshakeHello, &hello);
        hub.borrow_mut()
            .inboxes
            .entry(pb)
            .or_default()
            .push_back((pe, frame));
        let _ = (a, pa);
        let events = b.poll(1000);
        assert!(!b.has_channel(&pe));
        assert!(events.is_empty());
    }

    #[test]
    fn duplicate_open_channel_is_idempotent() {
        let (mut a, mut b, _hub, _pa, pb) = paired_nodes("idem");
        a.open_channel(&pb).expect("open1");
        a.open_channel(&pb).expect("open2"); // in flight: no-op
        handshake(&mut a, &mut b, &pb, 1000);
        a.open_channel(&pb).expect("open3"); // established: no-op
        assert!(a.has_channel(&pb));
    }

    // ---------- zero-delay live path ----------

    #[test]
    fn live_send_has_zero_artificial_delay() {
        let (mut a, mut b, hub, _pa, pb) = paired_nodes("nodelay");
        handshake(&mut a, &mut b, &pb, 1000);
        // Send WITHOUT any poll() in between: the frame must already be
        // in the hub for b. This is the zero-delay guarantee.
        a.send_data(&pb, b"instant", 1001).expect("send");
        let waiting = hub
            .borrow()
            .inboxes
            .get(&pb)
            .map(|q| q.len())
            .unwrap_or(0);
        assert_eq!(waiting, 1, "frame must be handed off synchronously");
        // And b receives it on its next poll.
        let events = b.poll(1002);
        assert!(events.iter().any(|e| format!("{e:?}").contains("DataReceived")));
        let inbound = b.take_inbound(&a.own_id());
        assert_eq!(inbound, vec![b"instant".to_vec()]);
    }

    #[test]
    fn replayed_link_frame_is_rejected() {
        let (mut a, mut b, hub, _pa, pb) = paired_nodes("replay");
        handshake(&mut a, &mut b, &pb, 1000);
        a.send_data(&pb, b"once", 1001).expect("send");
        // Duplicate the raw link frame in the hub.
        {
            let mut h = hub.borrow_mut();
            let q = h.inboxes.get_mut(&pb).expect("q");
            let dup = q.front().expect("frame").clone();
            q.push_back(dup);
        }
        b.poll(1002);
        let inbound = b.take_inbound(&a.own_id());
        assert_eq!(inbound.len(), 1, "replay must not produce a second delivery");
        assert_eq!(inbound[0], b"once");
    }

    // ---------- rekey ----------

    #[test]
    fn rekey_by_age_completes_and_data_flows() {
        let (mut a, mut b, _hub, pa, pb) = paired_nodes("rekey");
        handshake(&mut a, &mut b, &pb, 0);
        // Age past the rekey threshold; a's poll triggers a rekey offer.
        let _ = a.poll(3601);
        let ev_b: Vec<String> = b.poll(3602).iter().map(|e| format!("{e:?}")).collect();
        assert!(ev_b.iter().any(|e| e.contains("Rekeyed")), "b rekeyed: {ev_b:?}");
        let ev_a: Vec<String> = a.poll(3603).iter().map(|e| format!("{e:?}")).collect();
        assert!(ev_a.iter().any(|e| e.contains("Rekeyed")), "a rekeyed: {ev_a:?}");
        // Data flows on the new epoch both ways.
        a.send_data(&pb, b"after rekey a->b", 3604).expect("send");
        b.poll(3605);
        assert_eq!(b.take_inbound(&pa), vec![b"after rekey a->b".to_vec()]);
        b.send_data(&pa, b"after rekey b->a", 3606).expect("send");
        a.poll(3607);
        assert_eq!(a.take_inbound(&pb), vec![b"after rekey b->a".to_vec()]);
    }

    #[test]
    fn simultaneous_rekey_resolves_deterministically() {
        let (mut a, mut b, _hub, pa, pb) = paired_nodes("simrekey");
        handshake(&mut a, &mut b, &pb, 0);
        // Both sides' polls fire the age trigger before seeing the
        // other's offer: the tie-break must still converge.
        let _ = a.poll(3601);
        let _ = b.poll(3601);
        // Settle: each side processes whatever arrived.
        for _ in 0..4 {
            let _ = a.poll(3602);
            let _ = b.poll(3602);
        }
        // Exactly one epoch must win on each side, and data flows.
        a.send_data(&pb, b"converged", 3700).expect("send");
        b.poll(3701);
        assert_eq!(b.take_inbound(&pa), vec![b"converged".to_vec()]);
    }

    #[test]
    fn forged_rekey_offer_keeps_old_channel() {
        let (mut a, mut b, hub, _pa, pb) = paired_nodes("forgerekey");
        handshake(&mut a, &mut b, &pb, 0);
        // Attacker forges a rekey offer: valid shape, attacker's signature.
        let ide = identity(0xE5);
        let hs = InitiatorHandshake::new().unwrap();
        let forged = {
            // Build an auth-shaped blob signed by the attacker but
            // claiming to be... verify_auth_blob pins the identity, so
            // ANY forgery must fail. Use attacker's own signing.
            let eph = hs.hello();
            let mut blob = [0u8; REKEY_BLOB_LEN];
            blob[..32].copy_from_slice(&eph);
            blob[32..64].copy_from_slice(ide.public().as_bytes());
            let mut msg = [0u8; 64];
            msg[..32].copy_from_slice(&eph);
            msg[32..].copy_from_slice(b.own_id().as_bytes());
            let sig = ide.sign(&msg);
            blob[64..].copy_from_slice(sig.as_bytes());
            blob
        };
        let frame = encode_link(LinkKind::RekeyOffer, &forged);
        hub.borrow_mut()
            .inboxes
            .entry(pb)
            .or_default()
            .push_back((a.own_id(), frame));
        b.poll(100);
        // Old channel untouched: data still flows.
        a.send_data(&pb, b"still here", 101).expect("send");
        b.poll(102);
        assert_eq!(b.take_inbound(&a.own_id()), vec![b"still here".to_vec()]);
    }

    // ---------- offline queue ----------

    #[test]
    fn offline_message_queues_and_flushes_on_connect() {
        let (mut a, mut b, _hub, pa, pb) = paired_nodes("queue");
        // No handshake yet: send queues (and opportunistically hellos).
        a.send_data(&pb, b"queued hello", 1000).expect("send");
        assert_eq!(a.queue_len(), 1);
        // b was offline for data but the hello went out; drive handshake.
        b.poll(1001);
        a.poll(1002);
        assert!(a.has_channel(&pb));
        // Flush happened at ChannelReady: b gets the queued message.
        b.poll(1003);
        assert_eq!(b.take_inbound(&pa), vec![b"queued hello".to_vec()]);
        assert_eq!(a.queue_len(), 0);
    }

    #[test]
    fn queue_survives_node_restart() {
        let dir = test_dir("qrestart");
        let ida = identity(0xA1);
        let idb = identity(0xB2);
        let pb = PeerId::from_public(idb.public());
        let hub = Rc::new(RefCell::new(Hub {
            inboxes: HashMap::new(),
            adverts: Vec::new(),
            online: HashSet::new(),
        }));
        {
            let t = MemoryTransport { hub: Rc::clone(&hub), me: PeerId::from_public(ida.public()), send_fails: false };
            let mut a = MeshNode::new(ida, Box::new(t), &dir, &[0x33; 32]).expect("a");
            // Peer is a stranger to the queue path? No — queueing does
            // not require contact. Send to unreachable peer.
            a.send_data(&pb, b"persist me", 1000).expect("send");
            assert_eq!(a.queue_len(), 1);
        } // node dropped; queue file persists
        {
            let ida2 = identity(0xA1);
            let t = MemoryTransport { hub: Rc::clone(&hub), me: PeerId::from_public(ida2.public()), send_fails: false };
            let a2 = MeshNode::new(ida2, Box::new(t), &dir, &[0x33; 32]).expect("a2");
            assert_eq!(a2.queue_len(), 1, "queue must survive restart");
        }
    }

    #[test]
    fn queue_wrong_key_starts_empty_not_crash() {
        let dir = test_dir("qkey");
        let ida = identity(0xA1);
        let pb = PeerId::from_public(identity(0xB2).public());
        let hub = Rc::new(RefCell::new(Hub {
            inboxes: HashMap::new(),
            adverts: Vec::new(),
            online: HashSet::new(),
        }));
        {
            let t = MemoryTransport { hub: Rc::clone(&hub), me: PeerId::from_public(ida.public()), send_fails: false };
            let mut a = MeshNode::new(ida, Box::new(t), &dir, &[0x33; 32]).expect("a");
            a.send_data(&pb, b"x", 1000).expect("send");
        }
        // Reopen with a different key: decrypt fails → quarantine → empty.
        let ida2 = identity(0xA1);
        let t = MemoryTransport { hub: Rc::clone(&hub), me: PeerId::from_public(ida2.public()), send_fails: false };
        let a2 = MeshNode::new(ida2, Box::new(t), &dir, &[0x99; 32]).expect("a2");
        assert_eq!(a2.queue_len(), 0);
    }

    #[test]
    fn expired_queue_entries_notify_sender() {
        let (mut a, _b, _hub, _pa, pb) = paired_nodes("expire");
        // Queue to an unpaired peer (no contact → no handshake attempt).
        let stranger = PeerId([0xEE; 32]);
        let _ = pb;
        a.send_data(&stranger, b"doomed", 0).expect("send");
        assert_eq!(a.queue_len(), 1);
        // 8 days later: expired.
        let events = a.poll(8 * 24 * 3600);
        let expired: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                MeshEvent::MessageExpired { peer, id: _ } => Some(*peer),
                _ => None,
            })
            .collect();
        assert_eq!(expired, vec![stranger]);
        assert_eq!(a.queue_len(), 0);
    }

    // ---------- QR pairing ----------

    #[test]
    fn qr_pairing_pins_verified_identity() {
        let (mut a, mut b, _hub, pa, pb) = paired_nodes("qr");
        assert_eq!(a.contact_name(&pb), Some("Bob"));
        assert_eq!(b.contact_name(&pa), Some("Alice"));
        // Duplicate scan rejected.
        let card_b = b.set_own_card("Bob", "bob", 1000).expect("card");
        assert!(a.pair_via_qr(&card_b, 1001).is_err());
    }

    #[test]
    fn qr_tampered_card_rejected() {
        let (mut a, _b, _hub, _pa, _pb) = paired_nodes("qrtamper");
        let card = a.set_own_card("Alice", "alice", 1000).expect("card");
        let mut bad = card.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(a.pair_via_qr(&bad, 1001).is_err());
    }

    // ---------- discovery ----------

    #[test]
    fn discovery_advert_round_trip() {
        let (a, mut b, hub, pa, _pb) = paired_nodes("disco");
        let advert = a.advert_bytes("Alice", "alice", 1000).expect("advert");
        hub.borrow_mut().adverts.push(advert);
        let events = b.poll(1001);
        assert!(events.iter().any(|e| matches!(e, MeshEvent::PeerDiscovered(p) if *p == pa)));
        // Second poll: already known, no duplicate event.
        let events2 = b.poll(1002);
        assert!(events2.iter().all(|e| !matches!(e, MeshEvent::PeerDiscovered(_))));
    }

    #[test]
    fn discovery_tampered_advert_rejected() {
        let (a, mut b, hub, _pa, _pb) = paired_nodes("discotamper");
        let mut advert = a.advert_bytes("Alice", "alice", 1000).expect("advert");
        advert[50] ^= 0x02;
        hub.borrow_mut().adverts.push(advert);
        let events = b.poll(1001);
        assert!(events.iter().all(|e| !matches!(e, MeshEvent::PeerDiscovered(_))));
    }

    // ---------- voice walkie-talkie ----------

    fn voice_chunks(msg_id: [u8; 16], audio: &[u8]) -> Vec<VoiceChunk> {
        let total = ((audio.len() + MAX_VOICE_CHUNK - 1) / MAX_VOICE_CHUNK) as u32;
        audio
            .chunks(MAX_VOICE_CHUNK)
            .enumerate()
            .map(|(i, c)| VoiceChunk {
                msg_id,
                seq: i as u32,
                total,
                audio: c.to_vec(),
            })
            .collect()
    }

    #[test]
    fn voice_message_reassembles_out_of_order() {
        let (mut a, mut b, _hub, pa, pb) = paired_nodes("voice");
        handshake(&mut a, &mut b, &pb, 1000);
        let audio: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
        let mut chunks = voice_chunks([0xA0; 16], &audio);
        chunks.reverse(); // worst-case order
        for c in &chunks {
            a.send_voice(&pb, c, 1001).expect("send voice");
        }
        let events = b.poll(1002);
        let complete = events.iter().find_map(|e| match e {
            MeshEvent::VoiceMessageComplete { peer, msg_id: _, audio } => {
                assert_eq!(*peer, pa);
                Some(audio.clone())
            }
            _ => None,
        });
        assert_eq!(complete.expect("voice complete").as_slice(), audio.as_slice());
    }

    #[test]
    fn voice_queues_when_peer_offline() {
        let (mut a, mut b, _hub, pa, pb) = paired_nodes("voiceq");
        // No channel: voice chunk queues.
        let chunks = voice_chunks([0x11; 16], &vec![7u8; 100]);
        a.send_voice(&pb, &chunks[0], 1000).expect("send");
        assert_eq!(a.queue_len(), 1);
        // Connect: queued voice flushes and completes.
        b.poll(1001);
        a.poll(1002);
        let events = b.poll(1003);
        let done = events.iter().any(|e| matches!(
            e,
            MeshEvent::VoiceMessageComplete { peer, .. } if *peer == pa
        ));
        assert!(done, "queued voice must deliver on connect");
    }

    #[test]
    fn voice_chunk_validation() {
        let good = VoiceChunk { msg_id: [1; 16], seq: 0, total: 2, audio: vec![9; 100] };
        let bytes = good.to_bytes().expect("encode");
        let back = VoiceChunk::from_bytes(&bytes).expect("decode");
        assert_eq!(back.seq, 0);
        assert!(VoiceChunk::from_bytes(&bytes[..10]).is_err()); // truncated
        let bad = VoiceChunk { msg_id: [1; 16], seq: 5, total: 2, audio: vec![9; 10] };
        assert!(bad.to_bytes().is_err()); // seq >= total
    }

    // ---------- blind relay ----------

    fn onion_keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let secret = [seed; 32];
        let publ = transport::x25519(&secret, &transport::BASE_POINT);
        (secret, publ)
    }

    #[test]
    fn blind_relay_two_hops_relay_learns_nothing() {
        let (r1s, r1p) = onion_keypair(0x31);
        let (r2s, r2p) = onion_keypair(0x32);
        let (rcs, rcp) = onion_keypair(0xCC);
        let sender = PeerId([0x5E; 32]);
        let r1id = PeerId([0xA1; 32]);
        let r2id = PeerId([0xA2; 32]);
        let recip = PeerId([0xB0; 32]);
        let message = b"meet at the old oak at dawn";

        let packet = OnionPacket::build(
            message,
            &sender,
            &recip,
            &rcp,
            &[
                RelayHop { peer: r1id, onion_pub: r1p },
                RelayHop { peer: r2id, onion_pub: r2p },
            ],
        )
        .expect("build");

        // Relay 1 opens: learns ONLY next hop + opaque blob.
        let (next1, inner1) = match relay_open(&r1s, &packet).expect("r1 open") {
            RelayAction::Forward { next, packet } => (next, packet),
            RelayAction::Deliver { .. } => panic!("r1 must forward"),
        };
        assert_eq!(next1, r2id);
        // Privacy: r1's view contains no plaintext, no sender, no recipient.
        assert!(!inner1.windows(message.len()).any(|w| w == message));
        assert!(!inner1.windows(32).any(|w| w == sender.as_bytes()));
        assert!(!inner1.windows(32).any(|w| w == recip.as_bytes()));

        // Relay 2 opens: forwards to recipient, learns nothing either.
        let (next2, inner2) = match relay_open(&r2s, &inner1).expect("r2 open") {
            RelayAction::Forward { next, packet } => (next, packet),
            RelayAction::Deliver { .. } => panic!("r2 must forward"),
        };
        assert_eq!(next2, recip);
        assert!(!inner2.windows(message.len()).any(|w| w == message));

        // Recipient opens: gets sender + message.
        match relay_open(&rcs, &inner2).expect("recip open") {
            RelayAction::Deliver { sender: s, message: m } => {
                assert_eq!(s, sender);
                assert_eq!(m, message.to_vec());
            }
            RelayAction::Forward { .. } => panic!("recipient must deliver"),
        }
    }

    #[test]
    fn blind_relay_tampered_packet_rejected() {
        let (r1s, r1p) = onion_keypair(0x11);
        let (_r2s, r2p) = onion_keypair(0x12);
        let (_rcs, rcp) = onion_keypair(0x13);
        let packet = OnionPacket::build(
            b"hi",
            &PeerId([1; 32]),
            &PeerId([2; 32]),
            &rcp,
            &[
                RelayHop { peer: PeerId([3; 32]), onion_pub: r1p },
                RelayHop { peer: PeerId([4; 32]), onion_pub: r2p },
            ],
        )
        .expect("build");
        let mut bad = packet.clone();
        bad[60] ^= 0x01;
        assert!(relay_open(&r1s, &bad).is_err());
        // Wrong relay key cannot open either.
        let (w, _) = onion_keypair(0x77);
        assert!(relay_open(&w, &packet).is_err());
    }

    #[test]
    fn blind_relay_rejects_bad_params() {
        let (_, rcp) = onion_keypair(0x13);
        // One hop is below the 2-hop minimum.
        assert!(OnionPacket::build(
            b"hi",
            &PeerId([1; 32]),
            &PeerId([2; 32]),
            &rcp,
            &[RelayHop { peer: PeerId([3; 32]), onion_pub: [9; 32] }],
        )
        .is_err());
        // Oversize message.
        let big = vec![0u8; MAX_ONION_MESSAGE + 1];
        assert!(OnionPacket::build(
            &big,
            &PeerId([1; 32]),
            &PeerId([2; 32]),
            &rcp,
            &[
                RelayHop { peer: PeerId([3; 32]), onion_pub: [9; 32] },
                RelayHop { peer: PeerId([4; 32]), onion_pub: [9; 32] },
            ],
        )
        .is_err());
    }

    // ---------- link framing ----------

    #[test]
    fn link_frame_round_trip_and_validation() {
        let f = encode_link(LinkKind::Data, b"payload");
        let (kind, pt) = decode_link(&f).expect("decode");
        assert_eq!(kind, LinkKind::Data);
        assert_eq!(pt, b"payload");
        assert!(decode_link(b"junk").is_err());
        let mut bad = f.clone();
        bad[..4].copy_from_slice(b"XXXX");
        assert_eq!(decode_link(&bad).unwrap_err(), MeshError::MalformedLink);
        let mut badv = f.clone();
        badv[4] = 0xFF;
        assert!(decode_link(&badv).is_err());
        let mut badk = f.clone();
        badk[5] = 0x7F;
        assert_eq!(decode_link(&badk).unwrap_err(), MeshError::UnknownLinkKind);
        let big = vec![0u8; MAX_LINK_FRAME + 1];
        assert_eq!(decode_link(&big).unwrap_err(), MeshError::OversizedFrame);
    }

    #[test]
    fn peer_advert_sign_verify_round_trip() {
        let id = identity(0xAD);
        let advert = PeerAdvert::sign_with(id.public(), "Cara", "cara", &[0x99; 32], 5000, &|m| {
            id.sign(m)
        })
        .expect("sign");
        let bytes = advert.to_bytes();
        let back = PeerAdvert::from_bytes(&bytes).expect("parse");
        assert_eq!(back.peer_id(), PeerId::from_public(id.public()));
        assert_eq!(back.display_name(), "Cara");
        assert_eq!(back.onion_pub(), &[0x99; 32]);
        let mut bad = bytes.clone();
        bad[10] ^= 0x04;
        assert!(PeerAdvert::from_bytes(&bad).is_err());
    }
}
