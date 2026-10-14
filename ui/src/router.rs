//! Screen router: Sentinel ⇄ Conversations ⇄ Chat.
//!
//! [`Router`] is a drop-in replacement for
//! [`SentinelScreen`](crate::screen::SentinelScreen) as the UI core's
//! top-level screen: it implements [`Screen`], [`PixelScreen`] and
//! [`TextScreen`] by dispatching to whichever screen is active.
//!
//! ## Navigation
//!
//! * Sentinel, Escape with empty input → Conversations (when messaging
//!   is enabled via [`Router::enable_messaging`]).
//! * Conversations, Enter on a peer → nav request: the router surfaces
//!   the peer key through [`Router::take_open_request`]; the embedding
//!   app establishes the authenticated channel and calls
//!   [`Router::open_chat`] with a
//!   [`Conversation`](trv_core::messaging::Conversation).
//! * Conversations, Escape → Sentinel.
//! * Chat, Escape → Conversations (marks the peer seen).
//!
//! ## Transport hookup points (the UI does no network I/O)
//!
//! * [`Router::take_open_request`] — peer key needing a channel. The
//!   app runs `transport::establish_auth` over its own socket, builds
//!   `Conversation::new(channel, own, peer)`, and calls `open_chat`.
//! * [`Router::open_chat`] — installs the conversation as the active chat.
//! * [`Router::drain_outbound`] — sealed frames the UI produced
//!   (message sends, delivery receipts). The app transmits each over
//!   the peer's channel. Each frame is returned exactly once.
//! * [`Router::deliver_frame`] — incoming transport bytes for the
//!   active chat. Frames for any other peer (or with no chat open)
//!   are refused closed, never buffered: the app owns the
//!   conversations and must route bytes to the right one (or hold
//!   them until its chat opens).
//!
//! Android `app.rs` currently drives `SentinelScreen` directly; swapping
//! it for `Router::new(...)` is the hookup point (left untouched so
//! existing behavior is unchanged until the transport layer lands).

use std::collections::HashMap;
use std::rc::Rc;

use trv_backend::entitlement::Entitlement;
use trv_backend::history::HistoryStore;

use trv_core::messaging::Conversation;

use crate::chat::{ChatView, ReceiveOutcome};
use crate::conversations::ConversationsScreen;
use crate::platform::{PixelScreen, Screen, TextScreen, UiEvent};
use crate::screen::SentinelScreen;

/// Which screen is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Sentinel,
    Conversations,
    Chat,
}

/// What [`Router::deliver_frame`] did with incoming bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameOutcome {
    /// Fed to the active chat; carries what the frame produced.
    Handled(ReceiveOutcome),
    /// No chat is open, or the frame is not for the active peer.
    /// Refused closed — nothing displayed, logged, or answered.
    NoChatOpen,
}

/// Top-level UI router.
pub struct Router {
    sentinel: SentinelScreen,
    conversations: Option<ConversationsScreen>,
    chat: Option<ChatView>,
    route: Route,
    store: Option<Rc<HistoryStore>>,
    handles: HashMap<[u8; 32], String>,
    entitlement: Option<Entitlement>,
    pending_open: Option<[u8; 32]>,
    w: u32,
    h: u32,
}

impl Router {
    /// Sentinel-only router (messaging disabled until
    /// [`Router::enable_messaging`]).
    pub fn new(owner_handle: &str, w: u32, h: u32) -> Self {
        Router {
            sentinel: SentinelScreen::new(owner_handle, w, h),
            conversations: None,
            chat: None,
            route: Route::Sentinel,
            store: None,
            handles: HashMap::new(),
            entitlement: None,
            pending_open: None,
            w: w.max(64),
            h: h.max(64),
        }
    }

    /// Enable the Conversations/Chat routes.
    pub fn enable_messaging(
        &mut self,
        store: Rc<HistoryStore>,
        handles: HashMap<[u8; 32], String>,
        entitlement: Option<Entitlement>,
    ) {
        self.handles = handles;
        self.entitlement = entitlement;
        self.store = Some(Rc::clone(&store));
        self.conversations = Some(ConversationsScreen::new(
            store,
            self.handles.clone(),
            entitlement,
            self.w,
            self.h,
        ));
    }

    /// Replace the entitlement everywhere (sentinel UnlimitedEi gate,
    /// chat send gate + list hint).
    pub fn set_entitlement(&mut self, entitlement: Option<Entitlement>) {
        self.entitlement = entitlement;
        self.sentinel.set_entitlement(entitlement);
        if let Some(c) = self.conversations.as_mut() {
            c.set_entitlement(entitlement);
        }
        if let Some(c) = self.chat.as_mut() {
            c.set_entitlement(entitlement);
        }
    }

    /// Peer key waiting for the app to establish a channel for.
    /// Each key is returned exactly once.
    pub fn take_open_request(&mut self) -> Option<[u8; 32]> {
        if self.pending_open.is_none() {
            if let Some(c) = self.conversations.as_mut() {
                self.pending_open = c.take_open();
            }
        }
        self.pending_open.take()
    }

    /// Install an authenticated conversation as the active chat and
    /// navigate to it. The `Conversation` must already be bound to
    /// `peer` via the authenticated handshake.
    pub fn open_chat(&mut self, peer: [u8; 32], conversation: Conversation) {
        let store = match self.store.as_ref() {
            Some(s) => Rc::clone(s),
            None => return, // messaging not enabled: fail closed, stay put
        };
        let handle = self.handles.get(&peer).cloned();
        if let Some(c) = self.conversations.as_mut() {
            c.mark_seen(&peer);
        }
        self.chat = Some(ChatView::new(
            peer,
            handle,
            conversation,
            store,
            self.entitlement,
            self.w,
            self.h,
        ));
        self.route = Route::Chat;
    }

    /// Sealed frames the UI produced for the caller to transmit.
    pub fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
        self.chat
            .as_mut()
            .map(|c| c.drain_outbound())
            .unwrap_or_default()
    }

    /// Feed incoming transport bytes to the active chat.
    pub fn deliver_frame(&mut self, frame: &[u8]) -> FrameOutcome {
        match self.chat.as_mut() {
            Some(c) => FrameOutcome::Handled(c.receive(frame)),
            None => FrameOutcome::NoChatOpen,
        }
    }

    /// The peer of the currently open chat, if any.
    pub fn active_peer(&self) -> Option<[u8; 32]> {
        self.chat.as_ref().map(|c| *c.peer())
    }

    /// Current route (for tests).
    #[cfg(test)]
    fn route(&self) -> Route {
        self.route
    }

    fn go_conversations(&mut self) {
        if let Some(c) = self.conversations.as_mut() {
            c.refresh();
            self.route = Route::Conversations;
        }
    }
}

impl Screen for Router {
    fn on_event(&mut self, event: UiEvent) {
        // Track resizes for screens constructed later; each screen
        // also handles its own resize.
        if let UiEvent::Resize(w, h) = &event {
            self.w = (*w).max(64);
            self.h = (*h).max(64);
        }
        match self.route {
            Route::Sentinel => {
                // Escape with empty input leaves Sentinel for the
                // conversations list; any other event (including
                // Escape with text) goes to the Sentinel screen, whose
                // own Escape clears the input.
                if event == UiEvent::Escape
                    && self.sentinel.chat().input().is_empty()
                    && self.conversations.is_some()
                {
                    self.go_conversations();
                    return;
                }
                self.sentinel.on_event(event);
            }
            Route::Conversations => {
                if let Some(c) = self.conversations.as_mut() {
                    c.on_event(event);
                    if c.take_back() {
                        self.route = Route::Sentinel;
                    }
                } else {
                    self.route = Route::Sentinel;
                }
            }
            Route::Chat => {
                if let Some(c) = self.chat.as_mut() {
                    c.on_event(event);
                    if c.take_back() {
                        let peer = *c.peer();
                        self.chat = None;
                        if let Some(conv) = self.conversations.as_mut() {
                            conv.mark_seen(&peer);
                            conv.refresh();
                        }
                        self.route = Route::Conversations;
                    }
                } else {
                    self.route = Route::Conversations;
                }
            }
        }
    }
}

impl PixelScreen for Router {
    fn draw(&self, fb: &mut [u32], w: u32, h: u32) {
        match self.route {
            Route::Sentinel => self.sentinel.draw(fb, w, h),
            Route::Conversations => {
                if let Some(c) = &self.conversations {
                    c.draw(fb, w, h);
                } else {
                    self.sentinel.draw(fb, w, h);
                }
            }
            Route::Chat => {
                if let Some(c) = &self.chat {
                    c.draw(fb, w, h);
                } else if let Some(c) = &self.conversations {
                    c.draw(fb, w, h);
                } else {
                    self.sentinel.draw(fb, w, h);
                }
            }
        }
    }
}

impl TextScreen for Router {
    fn draw_text(&self, out: &mut dyn core::fmt::Write, cols: u32, rows: u32) {
        match self.route {
            Route::Sentinel => self.sentinel.draw_text(out, cols, rows),
            Route::Conversations => {
                if let Some(c) = &self.conversations {
                    c.draw_text(out, cols, rows);
                } else {
                    self.sentinel.draw_text(out, cols, rows);
                }
            }
            Route::Chat => {
                if let Some(c) = &self.chat {
                    c.draw_text(out, cols, rows);
                } else if let Some(c) = &self.conversations {
                    c.draw_text(out, cols, rows);
                } else {
                    self.sentinel.draw_text(out, cols, rows);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trv_backend::history::HistoryStore;
    use trv_core::crypto::ed25519;
    use trv_core::transport::{establish_auth, IdentityKey};

    const SEED_A: [u8; 32] = *b"router-test-seed-AAAAAAAAAAAAAAA";
    const SEED_B: [u8; 32] = *b"router-test-seed-BBBBBBBBBBBBBBB";
    const ISSUER_SEED: [u8; 32] = *b"test-ui-router-issuer-0000000000";

    fn live_entitlement() -> Entitlement {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let receipt = trv_backend::entitlement::issue(
            &ISSUER_SEED,
            trv_backend::subscriptions::Tier::Monthly,
            now,
            now + 30 * 86_400,
        )
        .expect("issue");
        let (_, ipub) = ed25519::generate(&ISSUER_SEED);
        trv_backend::entitlement::verify_and_check(ipub.as_bytes(), &receipt).expect("live")
    }

    fn test_store(tag: &str) -> Rc<HistoryStore> {
        let dir = std::env::temp_dir().join(format!(
            "trv-router-test-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        Rc::new(HistoryStore::open_with_iterations(&dir, "router-pass", 1000).expect("store"))
    }

    fn keys() -> (IdentityKey, IdentityKey, [u8; 32], [u8; 32]) {
        let (sa, pa) = ed25519::generate(&SEED_A);
        let (sb, pb) = ed25519::generate(&SEED_B);
        let ida = IdentityKey::new(sa, pa);
        let idb = IdentityKey::new(sb, pb);
        let ka = *ida.public().as_bytes();
        let kb = *idb.public().as_bytes();
        (ida, idb, ka, kb)
    }

    fn type_text(r: &mut Router, text: &str) {
        for c in text.chars() {
            r.on_event(UiEvent::Char(c));
        }
    }

    #[test]
    fn escape_from_sentinel_opens_conversations() {
        let mut r = Router::new("viewer", 640, 400);
        r.enable_messaging(test_store("a"), HashMap::new(), Some(live_entitlement()));
        assert_eq!(r.route(), Route::Sentinel);
        r.on_event(UiEvent::Escape);
        assert_eq!(r.route(), Route::Conversations);
        r.on_event(UiEvent::Escape);
        assert_eq!(r.route(), Route::Sentinel);
    }

    #[test]
    fn escape_with_input_stays_and_clears() {
        let mut r = Router::new("viewer", 640, 400);
        r.enable_messaging(test_store("b"), HashMap::new(), Some(live_entitlement()));
        type_text(&mut r, "hello");
        r.on_event(UiEvent::Escape);
        assert_eq!(r.route(), Route::Sentinel); // input cleared, not navigated
    }

    #[test]
    fn without_messaging_escape_stays_on_sentinel() {
        let mut r = Router::new("viewer", 640, 400);
        r.on_event(UiEvent::Escape);
        assert_eq!(r.route(), Route::Sentinel);
    }

    #[test]
    fn full_chat_flow_through_router() {
        let (ida, idb, _ka, kb) = keys();
        let store = test_store("c");
        // Seed history so the peer appears in the list.
        {
            use trv_backend::history::{HistoryMessage, HistoryStatus};
            let mut id = [0u8; 16];
            id[0] = 1;
            store
                .append(&HistoryMessage {
                    id,
                    peer: kb,
                    outgoing: false,
                    status: HistoryStatus::Delivered,
                    timestamp: 1,
                    text: "hey".into(),
                })
                .expect("seed");
        }
        let mut r = Router::new("viewer", 640, 400);
        let mut handles = HashMap::new();
        handles.insert(kb, "bob".to_string());
        r.enable_messaging(Rc::clone(&store), handles, Some(live_entitlement()));

        // Sentinel -> Conversations -> open request for bob.
        r.on_event(UiEvent::Escape);
        assert_eq!(r.route(), Route::Conversations);
        r.on_event(UiEvent::Enter);
        assert_eq!(r.take_open_request(), Some(kb));

        // App establishes the channel, hands the conversation over.
        let (ca, _cb) = establish_auth(&ida, &idb).expect("auth");
        r.open_chat(kb, Conversation::new(ca, ida.public(), idb.public()));
        assert_eq!(r.route(), Route::Chat);
        assert_eq!(r.active_peer(), Some(kb));

        // Send through the router's chat; outbound frame is surfaced.
        type_text(&mut r, "hi bob");
        r.on_event(UiEvent::Enter);
        let frames = r.drain_outbound();
        assert_eq!(frames.len(), 1);
        assert!(r.drain_outbound().is_empty()); // drained exactly once

        // Escape back to the list.
        r.on_event(UiEvent::Escape);
        assert_eq!(r.route(), Route::Conversations);
        assert_eq!(r.active_peer(), None);
    }

    #[test]
    fn deliver_frame_with_no_chat_is_refused() {
        let mut r = Router::new("viewer", 640, 400);
        r.enable_messaging(test_store("d"), HashMap::new(), Some(live_entitlement()));
        assert_eq!(r.deliver_frame(b"junk"), FrameOutcome::NoChatOpen);
    }

    #[test]
    fn router_renders_each_route() {
        let mut r = Router::new("viewer", 320, 200);
        r.enable_messaging(test_store("e"), HashMap::new(), Some(live_entitlement()));
        let mut out = String::new();
        r.draw_text(&mut out, 60, 24);
        assert!(out.contains("SENTINEL"));
        r.on_event(UiEvent::Escape);
        let mut out2 = String::new();
        r.draw_text(&mut out2, 60, 24);
        assert!(out2.contains("CONVERSATIONS"));
        let mut fb = vec![0u32; 320 * 200];
        r.draw(&mut fb, 320, 200);
        assert!(fb.iter().any(|&p| p != 0));
    }

    #[test]
    fn set_entitlement_propagates() {
        let mut r = Router::new("viewer", 320, 200);
        // Ghost tier: no messaging entitlement.
        r.enable_messaging(test_store("f"), HashMap::new(), None);
        let mut out = String::new();
        r.on_event(UiEvent::Escape);
        r.draw_text(&mut out, 60, 24);
        assert!(out.contains("locked"));
    }

    #[test]
    fn sentinel_route_gated_by_entitlement() {
        use crate::platform::TextScreen;
        // No entitlement: the Sentinel submit is denied.
        let mut r = Router::new("viewer", 320, 200);
        type_text(&mut r, "hello");
        r.on_event(UiEvent::Enter);
        let mut out = String::new();
        r.draw_text(&mut out, 60, 24);
        assert!(out.contains("Entitlement required"));
        // Presenting an entitlement unlocks the Sentinel route.
        r.set_entitlement(Some(live_entitlement()));
        let mut r2 = Router::new("viewer", 320, 200);
        r2.set_entitlement(Some(live_entitlement()));
        type_text(&mut r2, "hello");
        r2.on_event(UiEvent::Enter);
        let mut out2 = String::new();
        r2.draw_text(&mut out2, 60, 24);
        assert!(!out2.contains("Entitlement required"));
    }
}
