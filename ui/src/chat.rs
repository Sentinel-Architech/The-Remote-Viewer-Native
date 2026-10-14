//! Per-peer P2P chat screen.
//!
//! [`ChatView`] binds an authenticated
//! [`Conversation`](trv_core::messaging::Conversation) to a peer and a
//! shared [`HistoryStore`](trv_backend::history::HistoryStore). It owns
//! no network I/O: [`ChatView::send`] returns sealed frame bytes the
//! caller transmits, and [`ChatView::receive`] consumes incoming frame
//! bytes and returns any reply bytes (delivery receipts) for the caller
//! to transmit. Rendering follows the same pixel + text dual path as
//! [`SentinelScreen`](crate::screen::SentinelScreen).
//!
//! Sending is gated on the [`Feature::Messaging`] entitlement (see
//! [`gated`](crate::gated)): ghost-tier viewers cannot send. Receiving
//! and reading history are never gated.

use std::collections::HashSet;
use std::rc::Rc;

use trv_backend::entitlement::Entitlement;
use trv_backend::gates::{can_access, Feature};
use trv_backend::history::{HistoryMessage, HistoryStore};

use trv_core::messaging::{
    Conversation, MessageStatus, Received, MAX_TEXT_BYTES,
};

use crate::font::{GLYPH_H, GLYPH_W};
use crate::platform::{PixelScreen, Screen, TextScreen, UiEvent};
use crate::render::{self, color};

/// Shown when the Messaging gate denies a send.
pub const SEND_DENIED_MSG: &str =
    "Messaging needs a paid tier. Verify your receipt to send messages.";

/// What happened when the user hit send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// Sealed and queued for the caller to transmit. Carries the frame
    /// bytes; the caller MUST hand them to the transport layer.
    Sent(Vec<u8>),
    /// Ghost tier (or expired entitlement): nothing sealed, input kept.
    Denied,
    /// Message over the 8 KiB cap: nothing sealed, input kept.
    TooLong,
    /// Empty input: nothing to do.
    Empty,
}

/// What an incoming frame produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveOutcome {
    /// A new peer text was displayed (and a receipt was queued).
    Message,
    /// A delivery receipt arrived; one of our messages is now Delivered.
    Receipt,
    /// A typing hint arrived (transient indicator only).
    Typing,
    /// Duplicate frame: dropped silently.
    Duplicate,
    /// The frame failed closed (bad auth, wrong peer, malformed…).
    /// Nothing was displayed, logged, or answered.
    Rejected,
}

/// One displayed message row.
#[derive(Debug, Clone)]
struct ChatRow {
    id: [u8; 16],
    text: String,
    outgoing: bool,
    status: MessageStatus,
}

/// Per-peer conversation view.
///
/// Owns the [`Conversation`] (crypto + in-memory log), shares the
/// [`HistoryStore`] (durable log) by reference-count, and queues every
/// outbound frame (message frames from sends, receipt frames from
/// receives) for the caller to transmit via
/// [`ChatView::drain_outbound`].
pub struct ChatView {
    peer: [u8; 32],
    handle: Option<String>,
    conversation: Conversation,
    store: Rc<HistoryStore>,
    entitlement: Option<Entitlement>,
    rows: Vec<ChatRow>,
    input: String,
    scroll: u32,
    outbound: Vec<Vec<u8>>,
    typing: bool,
    denied_flash: bool,
    persist_failed: bool,
    w: u32,
    h: u32,
    pending_back: bool,
}

impl ChatView {
    /// Open the chat for `peer`. Loads persisted history from the
    /// store, then merges any in-memory conversation history not
    /// already persisted (matched by message ID — no duplicates).
    pub fn new(
        peer: [u8; 32],
        handle: Option<String>,
        conversation: Conversation,
        store: Rc<HistoryStore>,
        entitlement: Option<Entitlement>,
        w: u32,
        h: u32,
    ) -> Self {
        let mut rows = Vec::new();
        let mut seen_ids: HashSet<[u8; 16]> = HashSet::new();
        // Persisted history first (oldest-first append order).
        if let Ok(persisted) = store.load(&peer) {
            for m in persisted {
                seen_ids.insert(m.id);
                rows.push(ChatRow {
                    id: m.id,
                    text: m.text,
                    outgoing: m.outgoing,
                    status: match m.status {
                        trv_backend::history::HistoryStatus::Sent => MessageStatus::Sent,
                        trv_backend::history::HistoryStatus::Delivered => {
                            MessageStatus::Delivered
                        }
                    },
                });
            }
        }
        // Merge in-memory conversation entries not yet persisted.
        for s in conversation.history() {
            let id = *s.message.id();
            if seen_ids.insert(id) {
                rows.push(ChatRow {
                    id,
                    text: s.message.text().unwrap_or("").to_string(),
                    outgoing: s.outgoing,
                    status: s.status,
                });
            }
        }
        ChatView {
            peer,
            handle,
            conversation,
            store,
            entitlement,
            rows,
            input: String::new(),
            scroll: 0,
            outbound: Vec::new(),
            typing: false,
            denied_flash: false,
            persist_failed: false,
            w: w.max(64),
            h: h.max(64),
            pending_back: false,
        }
    }

    /// The peer this chat is with.
    pub fn peer(&self) -> &[u8; 32] {
        &self.peer
    }

    /// Replace the entitlement (e.g. after the viewer verifies a new
    /// receipt). Checked live on every send.
    pub fn set_entitlement(&mut self, entitlement: Option<Entitlement>) {
        self.entitlement = entitlement;
        self.denied_flash = false;
    }

    /// Frames the UI produced that the caller must transmit. Drains
    /// the queue: each frame is returned exactly once.
    pub fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbound)
    }

    /// True once Escape was pressed: the router should navigate back
    /// to the conversations list.
    pub fn take_back(&mut self) -> bool {
        std::mem::replace(&mut self.pending_back, false)
    }

    /// Short display name: the handle, or a truncated identity key.
    pub fn display_name(&self) -> String {
        match &self.handle {
            Some(h) => h.clone(),
            None => short_key(&self.peer),
        }
    }

    /// Number of displayed rows (for tests).
    #[cfg(test)]
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    fn persist(&mut self, msg: &HistoryMessage) {
        // Persistence is best-effort: crypto already succeeded, so a
        // store failure must not lose the send — it surfaces as a
        // warning row instead.
        if self.store.append(msg).is_err() {
            self.persist_failed = true;
        }
    }

    /// Send the current input through the Messaging gate, seal it,
    /// persist it, and queue the frame for transmission.
    pub fn send(&mut self) -> SendOutcome {
        let text = self.input.trim().to_string();
        if text.is_empty() {
            return SendOutcome::Empty;
        }
        if text.len() > MAX_TEXT_BYTES {
            return SendOutcome::TooLong;
        }
        if !can_access(Feature::Messaging, self.entitlement) {
            self.denied_flash = true;
            return SendOutcome::Denied;
        }
        let frame = match self.conversation.send_text(&text) {
            Ok(f) => f,
            Err(_) => return SendOutcome::TooLong, // fail closed; input kept
        };
        // The conversation logged the sealed message; persist it.
        // (Extract first: the borrow of `conversation.history()` must
        // end before the mutable `persist` call.)
        let to_persist: Option<HistoryMessage> = self
            .conversation
            .history()
            .last()
            .and_then(|s| HistoryMessage::from_messaging(&self.peer, s).ok());
        if let Some(hm) = to_persist {
            let id = hm.id;
            let status = match hm.status {
                trv_backend::history::HistoryStatus::Sent => MessageStatus::Sent,
                trv_backend::history::HistoryStatus::Delivered => MessageStatus::Delivered,
            };
            self.persist(&hm);
            self.rows.push(ChatRow {
                id,
                text: text.clone(),
                outgoing: true,
                status,
            });
        }
        self.outbound.push(frame.clone());
        self.input.clear();
        self.scroll = 0;
        self.denied_flash = false;
        SendOutcome::Sent(frame)
    }

    /// Feed one incoming transport frame into the conversation.
    /// Returns what happened; any reply frame (delivery receipt) is
    /// queued in [`ChatView::drain_outbound`].
    pub fn receive(&mut self, frame: &[u8]) -> ReceiveOutcome {
        match self.conversation.receive_frame(frame) {
            Ok(Received::Text {
                message,
                receipt_frame,
            }) => {
                let text = message.text().unwrap_or("").to_string();
                let hm = HistoryMessage {
                    id: *message.id(),
                    peer: self.peer,
                    outgoing: false,
                    status: trv_backend::history::HistoryStatus::Delivered,
                    timestamp: message.timestamp(),
                    text: text.clone(),
                };
                self.persist(&hm);
                self.rows.push(ChatRow {
                    id: *message.id(),
                    text,
                    outgoing: false,
                    status: MessageStatus::Delivered,
                });
                self.outbound.push(receipt_frame);
                self.scroll = 0;
                ReceiveOutcome::Message
            }
            Ok(Received::Receipt { acked_id }) => {
                for row in self.rows.iter_mut() {
                    if row.id == acked_id && row.outgoing {
                        row.status = MessageStatus::Delivered;
                    }
                }
                ReceiveOutcome::Receipt
            }
            Ok(Received::Typing) => {
                self.typing = true;
                ReceiveOutcome::Typing
            }
            Ok(Received::Duplicate) => ReceiveOutcome::Duplicate,
            Err(_) => ReceiveOutcome::Rejected,
        }
    }

    fn layout(&self) -> ChatLayout {
        ChatLayout::new(self.w, self.h)
    }

    /// All wrapped rows, oldest first: (outgoing, status, line).
    fn wrapped_rows(&self, max_cells: u32) -> Vec<(bool, MessageStatus, String)> {
        let mut out = Vec::new();
        for r in &self.rows {
            let who = if r.outgoing { "you" } else { "peer" };
            let mark = match (r.outgoing, r.status) {
                (true, MessageStatus::Sent) => " (sent)",
                (true, MessageStatus::Delivered) => " (delivered)",
                _ => "",
            };
            for line in render::wrap_text(&format!("[{who}]{mark} {}", r.text), max_cells) {
                out.push((r.outgoing, r.status, line));
            }
        }
        out
    }

    fn visible_rows(
        &self,
        max_cells: u32,
        max_lines: u32,
    ) -> Vec<(bool, MessageStatus, String)> {
        let rows = self.wrapped_rows(max_cells);
        let total = rows.len() as u32;
        let n = max_lines.min(total);
        let end = total.saturating_sub(self.scroll).min(total);
        let start = end.saturating_sub(n);
        rows[start as usize..end as usize].to_vec()
    }
}

/// Pixel layout of the chat screen.
#[derive(Debug, Clone, Copy)]
struct ChatLayout {
    w: u32,
    h: u32,
    header_h: u32,
    input_h: u32,
    send_w: u32,
    pad: u32,
}

impl ChatLayout {
    fn new(w: u32, h: u32) -> Self {
        ChatLayout {
            w,
            h,
            header_h: 28,
            input_h: 32,
            send_w: 72,
            pad: 8,
        }
    }

    fn msg_top(&self) -> u32 {
        self.header_h + self.pad
    }

    fn msg_bottom(&self) -> u32 {
        self.h.saturating_sub(self.input_h + self.pad * 2)
    }

    fn input_y(&self) -> u32 {
        self.h.saturating_sub(self.input_h + self.pad)
    }

    fn send_rect(&self) -> (u32, u32, u32, u32) {
        let x = self.w.saturating_sub(self.send_w + self.pad);
        (x, self.input_y(), self.send_w, self.input_h)
    }

    fn input_rect(&self) -> (u32, u32, u32, u32) {
        let (sx, _, _, _) = self.send_rect();
        (
            self.pad,
            self.input_y(),
            sx.saturating_sub(self.pad * 2),
            self.input_h,
        )
    }
}

/// First 8 hex chars of an identity key, for display.
fn short_key(key: &[u8; 32]) -> String {
    key.iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        + "…"
}

impl Screen for ChatView {
    fn on_event(&mut self, event: UiEvent) {
        let lay = self.layout();
        match event {
            UiEvent::Char(c) => {
                if !c.is_control() {
                    self.input.push(c);
                    self.denied_flash = false;
                }
            }
            UiEvent::Backspace => {
                self.input.pop();
            }
            UiEvent::Enter => {
                let _ = self.send();
            }
            UiEvent::Escape => {
                self.pending_back = true;
            }
            UiEvent::Scroll(d) => {
                let max_cells = render::cells_for(lay.w.saturating_sub(lay.pad * 4)).max(8);
                let area_h = lay.msg_bottom().saturating_sub(lay.msg_top());
                let max_lines = (area_h / GLYPH_H).max(1);
                let total = self.wrapped_rows(max_cells).len() as u32;
                let max_scroll = total.saturating_sub(max_lines.min(total));
                if d < 0 {
                    self.scroll = self.scroll.saturating_add((-d) as u32).min(max_scroll);
                } else {
                    self.scroll = self.scroll.saturating_sub(d as u32);
                }
            }
            UiEvent::Tap(x, y) => {
                let (sx, sy, sw, sh) = lay.send_rect();
                if x >= sx && x < sx + sw && y >= sy && y < sy + sh {
                    let _ = self.send();
                }
            }
            UiEvent::Resize(w, h) => {
                self.w = w.max(64);
                self.h = h.max(64);
                self.scroll = 0;
            }
            UiEvent::Quit => {}
        }
    }
}

impl PixelScreen for ChatView {
    fn draw(&self, fb: &mut [u32], w: u32, h: u32) {
        if fb.len() < (w as usize).saturating_mul(h as usize) {
            return;
        }
        let lay = ChatLayout::new(w, h);
        render::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // Header: peer name + back hint.
        render::fill_rect(fb, w, h, 0, 0, w, lay.header_h, color::PANEL);
        render::fill_rect(fb, w, h, 0, lay.header_h - 1, w, 1, color::PANEL_EDGE);
        let title = format!("CHAT — {}", self.display_name());
        render::draw_text(fb, w, h, lay.pad + 2, 10, &title, color::ACCENT);
        let back = "esc: back";
        let back_x = w.saturating_sub((back.len() as u32) * GLYPH_W + lay.pad + 2);
        render::draw_text(fb, w, h, back_x, 10, back, color::DIM);

        // Messages.
        let max_cells = render::cells_for(lay.w.saturating_sub(lay.pad * 4)).max(8);
        let area_h = lay.msg_bottom().saturating_sub(lay.msg_top());
        let max_lines = (area_h / GLYPH_H).max(1);
        let mut y = lay.msg_top() + 4;
        for (outgoing, _status, line) in self.visible_rows(max_cells, max_lines) {
            if y + GLYPH_H > lay.msg_bottom() {
                break;
            }
            let bubble_c = if outgoing {
                color::YOU_BUBBLE
            } else {
                color::SENT_BUBBLE
            };
            let text_w = (line.chars().count() as u32) * GLYPH_W;
            let bw = text_w + 16;
            let bx = if outgoing {
                w.saturating_sub(bw + lay.pad)
            } else {
                lay.pad
            };
            render::fill_rect(fb, w, h, bx, y, bw, GLYPH_H + 6, bubble_c);
            render::draw_text(fb, w, h, bx + 8, y + 3, &line, color::TEXT);
            y += GLYPH_H + 10;
        }

        // Denied / warning flash line above the input box.
        let mut flash_y = lay.input_y().saturating_sub(GLYPH_H + 6);
        if self.denied_flash {
            render::draw_text(
                fb,
                w,
                h,
                lay.pad + 2,
                flash_y,
                SEND_DENIED_MSG,
                color::ACCENT,
            );
            flash_y = flash_y.saturating_sub(GLYPH_H + 4);
        }
        if self.persist_failed {
            render::draw_text(
                fb,
                w,
                h,
                lay.pad + 2,
                flash_y,
                "warning: message sent but history save failed",
                color::DIM,
            );
        }
        if self.typing {
            let t = "peer is typing…";
            let tx = w.saturating_sub((t.len() as u32) * GLYPH_W + lay.pad + 2);
            render::draw_text(fb, w, h, tx, flash_y, t, color::DIM);
        }

        // Input box.
        let (ix, iy, iw, ih) = lay.input_rect();
        render::fill_rect(fb, w, h, ix, iy, iw, ih, color::INPUT_BG);
        render::fill_rect(fb, w, h, ix, iy, iw, 1, color::PANEL_EDGE);
        render::fill_rect(fb, w, h, ix, iy + ih - 1, iw, 1, color::PANEL_EDGE);
        let mut tx = render::draw_text(fb, w, h, ix + 8, iy + 12, "> ", color::DIM);
        let max_input_cells = render::cells_for(iw.saturating_sub(16)).max(1);
        let shown: String = self
            .input
            .chars()
            .rev()
            .take(max_input_cells as usize)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        tx = render::draw_text(fb, w, h, tx, iy + 12, &shown, color::TEXT);
        render::fill_rect(fb, w, h, tx + 2, iy + 12, 6, GLYPH_H, color::ACCENT);

        // Send button.
        let (sx, sy, sw, sh) = lay.send_rect();
        render::fill_rect(fb, w, h, sx, sy, sw, sh, color::SEND_BG);
        let label = "SEND";
        let lx = sx + (sw.saturating_sub((label.len() as u32) * GLYPH_W)) / 2;
        render::draw_text(fb, w, h, lx, sy + 12, label, color::BLACK);
    }
}

impl TextScreen for ChatView {
    fn draw_text(&self, out: &mut dyn core::fmt::Write, cols: u32, rows: u32) {
        let cols = cols.max(20);
        let rows = rows.max(8);
        let _ = writeln!(out, "== CHAT — {} ==", self.display_name());
        let max_lines = rows.saturating_sub(5);
        for (outgoing, status, line) in self.visible_rows(cols, max_lines) {
            let who = if outgoing { "you" } else { "peer" };
            let mark = match (outgoing, status) {
                (true, MessageStatus::Sent) => "~",
                (true, MessageStatus::Delivered) => "✓",
                _ => " ",
            };
            let _ = writeln!(out, "[{who}{mark}] {line}");
        }
        if self.denied_flash {
            let _ = writeln!(out, "{SEND_DENIED_MSG}");
        }
        if self.persist_failed {
            let _ = writeln!(out, "(warning: history save failed)");
        }
        let _ = writeln!(out, "{}", "-".repeat(cols as usize));
        let _ = writeln!(out, "> {}", self.input);
        let _ = writeln!(out, "[Enter send · esc back]");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{Screen, UiEvent};
    use trv_backend::history::HistoryStore;
    use trv_core::crypto::ed25519;
    use trv_core::transport::{establish_auth, IdentityKey};

    const SEED_A: [u8; 32] = *b"chat-test-seed-AAAAAAAAAAAAAAAAA";
    const SEED_B: [u8; 32] = *b"chat-test-seed-BBBBBBBBBBBBBBBBB";

    fn keys() -> (IdentityKey, IdentityKey, [u8; 32], [u8; 32]) {
        let (sa, pa) = ed25519::generate(&SEED_A);
        let (sb, pb) = ed25519::generate(&SEED_B);
        let ida = IdentityKey::new(sa, pa);
        let idb = IdentityKey::new(sb, pb);
        let ka = *ida.public().as_bytes();
        let kb = *idb.public().as_bytes();
        (ida, idb, ka, kb)
    }

    fn two_chats() -> (ChatView, ChatView, Rc<HistoryStore>, Rc<HistoryStore>) {
        let (ida, idb, ka, kb) = keys();
        let (ca, cb) = establish_auth(&ida, &idb).expect("auth");
        let dir = std::env::temp_dir().join(format!(
            "trv-chat-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let sa = Rc::new(
            HistoryStore::open_with_iterations(&dir.join("a"), "pass-a", 1000)
                .expect("store a"),
        );
        let sb = Rc::new(
            HistoryStore::open_with_iterations(&dir.join("b"), "pass-b", 1000)
                .expect("store b"),
        );
        let va = ChatView::new(kb, Some("bob".into()), Conversation::new(ca, ida.public(), idb.public()), Rc::clone(&sa), Some(live_entitlement()), 640, 400);
        let vb = ChatView::new(ka, Some("alice".into()), Conversation::new(cb, idb.public(), ida.public()), Rc::clone(&sb), Some(live_entitlement()), 640, 400);
        (va, vb, sa, sb)
    }

    // --- entitlement helpers (mirrors gated.rs tests) ---
    const ISSUER_SEED: [u8; 32] = *b"test-ui-chat-issuer-000000000000";

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

    fn type_text(v: &mut ChatView, text: &str) {
        for c in text.chars() {
            v.on_event(UiEvent::Char(c));
        }
    }

    #[test]
    fn send_receive_round_trip_with_receipt() {
        let (mut va, mut vb, _sa, _sb) = two_chats();
        type_text(&mut va, "hello bob");
        let frame = match va.send() {
            SendOutcome::Sent(f) => f,
            o => panic!("expected Sent, got {o:?}"),
        };
        // A delivers to B; B's receipt goes back to A.
        assert_eq!(vb.receive(&frame), ReceiveOutcome::Message);
        assert_eq!(vb.row_count(), 1);
        let receipts = vb.drain_outbound();
        assert_eq!(receipts.len(), 1);
        assert_eq!(va.receive(&receipts[0]), ReceiveOutcome::Receipt);
        // A's row is now Delivered.
        let mut out = String::new();
        va.draw_text(&mut out, 60, 24);
        assert!(out.contains('✓'), "expected delivered mark: {out}");
    }

    #[test]
    fn history_persists_across_chatview_instances() {
        let (ida, idb, ka, kb) = keys();
        let (ca, _cb) = establish_auth(&ida, &idb).expect("auth");
        let dir = std::env::temp_dir().join(format!(
            "trv-chat-persist-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let store = Rc::new(
            HistoryStore::open_with_iterations(&dir, "persist-pass", 1000).expect("store"),
        );
        let mut v1 = ChatView::new(
            kb,
            None,
            Conversation::new(ca, ida.public(), idb.public()),
            Rc::clone(&store),
            Some(live_entitlement()),
            640,
            400,
        );
        type_text(&mut v1, "remember me");
        assert!(matches!(v1.send(), SendOutcome::Sent(_)));
        drop(v1);
        // Fresh conversation, same store: history must survive.
        let (ca2, _) = establish_auth(&ida, &idb).expect("auth2");
        let v2 = ChatView::new(
            kb,
            None,
            Conversation::new(ca2, ida.public(), idb.public()),
            Rc::clone(&store),
            Some(live_entitlement()),
            640,
            400,
        );
        assert_eq!(v2.row_count(), 1);
        let _ = ka;
    }

    #[test]
    fn ghost_cannot_send() {
        let (mut va, _vb, _sa, _sb) = two_chats();
        va.set_entitlement(None);
        type_text(&mut va, "nope");
        assert_eq!(va.send(), SendOutcome::Denied);
        assert!(va.drain_outbound().is_empty());
        // Input kept for retry after entitling.
        assert_eq!(va.input, "nope");
        let mut out = String::new();
        va.draw_text(&mut out, 60, 24);
        assert!(out.contains("paid tier"));
    }

    #[test]
    fn oversized_message_rejected_in_ui() {
        let (mut va, _vb, _sa, _sb) = two_chats();
        va.input = "x".repeat(MAX_TEXT_BYTES + 1);
        assert_eq!(va.send(), SendOutcome::TooLong);
        assert!(va.drain_outbound().is_empty());
    }

    #[test]
    fn wrong_peer_frame_rejected() {
        let (mut va, _vb, _sa, _sb) = two_chats();
        // Random garbage fails closed.
        assert_eq!(va.receive(b"garbage"), ReceiveOutcome::Rejected);
        assert_eq!(va.row_count(), 0);
    }

    #[test]
    fn escape_requests_back() {
        let (mut va, _vb, _sa, _sb) = two_chats();
        assert!(!va.take_back());
        va.on_event(UiEvent::Escape);
        assert!(va.take_back());
        assert!(!va.take_back());
    }

    #[test]
    fn enter_sends_typed_text() {
        let (mut va, mut vb, _sa, _sb) = two_chats();
        type_text(&mut va, "hi");
        va.on_event(UiEvent::Enter);
        assert_eq!(va.row_count(), 1);
        let frames = va.drain_outbound();
        assert_eq!(frames.len(), 1);
        assert_eq!(vb.receive(&frames[0]), ReceiveOutcome::Message);
    }

    #[test]
    fn draw_paints_framebuffer() {
        let (mut va, _vb, _sa, _sb) = two_chats();
        type_text(&mut va, "hello");
        let _ = va.send();
        let mut fb = vec![0u32; 320 * 200];
        va.draw(&mut fb, 320, 200);
        let painted = fb.iter().filter(|&&p| p != 0).count();
        assert!(painted > 500, "expected painted pixels, got {painted}");
    }

    #[test]
    fn draw_text_renders_chat() {
        let (mut va, mut vb, _sa, _sb) = two_chats();
        type_text(&mut va, "hello");
        let frames = match va.send() {
            SendOutcome::Sent(f) => vec![f],
            o => panic!("{o:?}"),
        };
        vb.receive(&frames[0]);
        let mut out = String::new();
        vb.draw_text(&mut out, 60, 24);
        assert!(out.contains("CHAT"));
        assert!(out.contains("hello"));
        assert!(out.contains("bob") || out.contains("alice"));
    }

    #[test]
    fn empty_send_is_noop() {
        let (mut va, _vb, _sa, _sb) = two_chats();
        assert_eq!(va.send(), SendOutcome::Empty);
    }
}
