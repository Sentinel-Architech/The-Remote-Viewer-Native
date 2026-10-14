//! Conversations list screen.
//!
//! [`ConversationsScreen`] lists every peer with message history in
//! the shared [`HistoryStore`](trv_backend::history::HistoryStore):
//! display handle (or a truncated identity key), last-message preview,
//! and unread count. Scroll moves the selection, Enter opens the chat
//! (surfacing a nav request the router hands to the embedding app),
//! Escape goes back. Rendering follows the same pixel + text dual path
//! as the other screens.
//!
//! Reading the list is never gated; sending inside a chat is (see
//! [`chat`](crate::chat)).

use std::collections::HashMap;
use std::rc::Rc;

use trv_backend::entitlement::Entitlement;
use trv_backend::gates::{can_access, Feature};
use trv_backend::history::HistoryStore;

use crate::font::{GLYPH_H, GLYPH_W};
use crate::platform::{PixelScreen, Screen, TextScreen, UiEvent};
use crate::render::{self, color};

/// One row in the conversations list.
#[derive(Debug, Clone)]
struct PeerRow {
    peer: [u8; 32],
    name: String,
    preview: String,
    unread: usize,
    total: usize,
}

/// Conversations list. Shares the [`HistoryStore`] by reference-count
/// with any open [`ChatView`](crate::chat::ChatView).
pub struct ConversationsScreen {
    store: Rc<HistoryStore>,
    handles: HashMap<[u8; 32], String>,
    entitlement: Option<Entitlement>,
    rows: Vec<PeerRow>,
    selected: usize,
    /// peer -> message count the viewer had seen at last open.
    seen: HashMap<[u8; 32], usize>,
    w: u32,
    h: u32,
    pending_open: Option<[u8; 32]>,
    pending_back: bool,
}

impl ConversationsScreen {
    pub fn new(
        store: Rc<HistoryStore>,
        handles: HashMap<[u8; 32], String>,
        entitlement: Option<Entitlement>,
        w: u32,
        h: u32,
    ) -> Self {
        let mut s = ConversationsScreen {
            store,
            handles,
            entitlement,
            rows: Vec::new(),
            selected: 0,
            seen: HashMap::new(),
            w: w.max(64),
            h: h.max(64),
            pending_open: None,
            pending_back: false,
        };
        s.refresh();
        s
    }

    /// Replace the entitlement (e.g. after the viewer verifies a new
    /// receipt).
    pub fn set_entitlement(&mut self, entitlement: Option<Entitlement>) {
        self.entitlement = entitlement;
    }

    /// Rebuild rows from the store. Call after returning from a chat
    /// so previews and unread counts are current.
    pub fn refresh(&mut self) {
        let mut rows = Vec::new();
        if let Ok(peers) = self.store.list_peers() {
            for peer in peers {
                let total = self
                    .store
                    .load(&peer)
                    .map(|v| v.len())
                    .unwrap_or(0);
                let preview = self
                    .store
                    .load(&peer)
                    .ok()
                    .and_then(|v| v.last().map(|m| preview_of(&m.text)))
                    .unwrap_or_default();
                let seen = self.seen.get(&peer).copied().unwrap_or(0);
                let name = self
                    .handles
                    .get(&peer)
                    .cloned()
                    .unwrap_or_else(|| short_key(&peer));
                rows.push(PeerRow {
                    peer,
                    name,
                    preview,
                    unread: total.saturating_sub(seen),
                    total,
                });
            }
        }
        // Most recent activity first: rows with the highest totals
        // sort first (append order == recency within a log; across
        // logs we approximate with total count). Stable and simple.
        rows.sort_by(|a, b| b.total.cmp(&a.total));
        self.rows = rows;
        self.selected = self.selected.min(self.rows.len().saturating_sub(1));
    }

    /// Mark a peer's messages as seen (call when its chat opens).
    pub fn mark_seen(&mut self, peer: &[u8; 32]) {
        let total = self
            .rows
            .iter()
            .find(|r| &r.peer == peer)
            .map(|r| r.total)
            .unwrap_or(0);
        self.seen.insert(*peer, total);
        self.refresh();
    }

    /// Unread count for one peer (for tests).
    #[cfg(test)]
    pub fn unread_for(&self, peer: &[u8; 32]) -> usize {
        self.rows
            .iter()
            .find(|r| &r.peer == peer)
            .map(|r| r.unread)
            .unwrap_or(0)
    }

    /// Row count (for tests).
    #[cfg(test)]
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Nav request: the peer whose chat should open. The router hands
    /// this to the embedding app, which establishes the authenticated
    /// channel and calls back with a `Conversation`.
    pub fn take_open(&mut self) -> Option<[u8; 32]> {
        self.pending_open.take()
    }

    /// True once Escape was pressed: the router should go back to the
    /// Sentinel screen.
    pub fn take_back(&mut self) -> bool {
        std::mem::replace(&mut self.pending_back, false)
    }

    fn layout(&self) -> ListLayout {
        ListLayout::new()
    }

    fn move_selection(&mut self, delta: i32) {
        if self.rows.is_empty() {
            return;
        }
        let n = self.rows.len() as i32;
        let cur = self.selected as i32;
        self.selected = (cur + delta).clamp(0, n - 1) as usize;
    }

    fn open_selected(&mut self) {
        if let Some(row) = self.rows.get(self.selected) {
            self.pending_open = Some(row.peer);
        }
    }

    fn row_at_y(&self, y: u32) -> Option<usize> {
        let lay = self.layout();
        let row_h = GLYPH_H + 14;
        let first = lay.list_top() + 4;
        if y < first {
            return None;
        }
        let idx = (y - first) / row_h;
        let i = idx as usize;
        if i < self.rows.len() {
            Some(i)
        } else {
            None
        }
    }
}

/// First 40 chars of the last message, single-line.
fn preview_of(text: &str) -> String {
    let flat: String = text.chars().filter(|c| !c.is_control()).collect();
    let mut s: String = flat.chars().take(40).collect();
    if flat.chars().count() > 40 {
        s.push('…');
    }
    s
}

/// First 8 hex chars of an identity key, for display.
fn short_key(key: &[u8; 32]) -> String {
    key.iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        + "…"
}

/// Pixel layout of the list screen.
#[derive(Debug, Clone, Copy)]
struct ListLayout {
    header_h: u32,
    pad: u32,
}

impl ListLayout {
    fn new() -> Self {
        ListLayout {
            header_h: 28,
            pad: 8,
        }
    }

    fn list_top(&self) -> u32 {
        self.header_h + self.pad
    }
}

impl Screen for ConversationsScreen {
    fn on_event(&mut self, event: UiEvent) {
        match event {
            UiEvent::Char(c) => {
                // j/k move like a pager; anything else is ignored here.
                match c {
                    'j' => self.move_selection(1),
                    'k' => self.move_selection(-1),
                    _ => {}
                }
            }
            UiEvent::Backspace => {}
            UiEvent::Enter => self.open_selected(),
            UiEvent::Escape => {
                self.pending_back = true;
            }
            UiEvent::Scroll(d) => self.move_selection(if d < 0 { 1 } else { -1 }),
            UiEvent::Tap(_x, y) => {
                if let Some(i) = self.row_at_y(y) {
                    self.selected = i;
                    self.open_selected();
                }
            }
            UiEvent::Resize(w, h) => {
                self.w = w.max(64);
                self.h = h.max(64);
            }
            UiEvent::Quit => {}
        }
    }
}

impl PixelScreen for ConversationsScreen {
    fn draw(&self, fb: &mut [u32], w: u32, h: u32) {
        if fb.len() < (w as usize).saturating_mul(h as usize) {
            return;
        }
        let lay = ListLayout::new();
        render::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

        // Header.
        render::fill_rect(fb, w, h, 0, 0, w, lay.header_h, color::PANEL);
        render::fill_rect(fb, w, h, 0, lay.header_h - 1, w, 1, color::PANEL_EDGE);
        render::draw_text(fb, w, h, lay.pad + 2, 10, "CONVERSATIONS", color::ACCENT);
        if !can_access(Feature::Messaging, self.entitlement) {
            let lock = "messaging locked — verify receipt to send";
            let lx = w.saturating_sub((lock.len() as u32) * GLYPH_W + lay.pad + 2);
            render::draw_text(fb, w, h, lx, 10, lock, color::DIM);
        }

        // Rows.
        let row_h = GLYPH_H + 14;
        let mut y = lay.list_top() + 4;
        if self.rows.is_empty() {
            render::draw_text(
                fb,
                w,
                h,
                lay.pad + 2,
                y,
                "No conversations yet. Add a contact to start.",
                color::DIM,
            );
            return;
        }
        for (i, row) in self.rows.iter().enumerate() {
            if y + row_h > h {
                break;
            }
            if i == self.selected {
                render::fill_rect(fb, w, h, lay.pad, y, w - lay.pad * 2, row_h, color::PANEL);
            }
            let name_line = if row.unread > 0 {
                format!("{}  ({} new)", row.name, row.unread)
            } else {
                row.name.clone()
            };
            let nc = if row.unread > 0 { color::ACCENT } else { color::TEXT };
            render::draw_text(fb, w, h, lay.pad + 8, y + 3, &name_line, nc);
            if !row.preview.is_empty() {
                render::draw_text(
                    fb,
                    w,
                    h,
                    lay.pad + 8,
                    y + 3 + GLYPH_H + 2,
                    &row.preview,
                    color::DIM,
                );
            }
            y += row_h;
        }
    }
}

impl TextScreen for ConversationsScreen {
    fn draw_text(&self, out: &mut dyn core::fmt::Write, cols: u32, rows: u32) {
        let cols = cols.max(20);
        let rows = rows.max(8);
        let _ = writeln!(out, "== CONVERSATIONS ==");
        if !can_access(Feature::Messaging, self.entitlement) {
            let _ = writeln!(out, "(messaging locked — verify receipt to send)");
        }
        if self.rows.is_empty() {
            let _ = writeln!(out, "No conversations yet.");
        }
        let max_rows = rows.saturating_sub(4) as usize;
        for (i, row) in self.rows.iter().take(max_rows).enumerate() {
            let sel = if i == self.selected { ">" } else { " " };
            let new = if row.unread > 0 {
                format!(" ({} new)", row.unread)
            } else {
                String::new()
            };
            let _ = writeln!(out, "{sel} {}{new}", row.name);
            if !row.preview.is_empty() {
                let _ = writeln!(out, "    {}", row.preview);
            }
        }
        let _ = writeln!(out, "{}", "-".repeat(cols as usize));
        let _ = writeln!(out, "[scroll/j/k select · Enter open · esc back]");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{Screen, UiEvent};
    use trv_backend::history::{HistoryMessage, HistoryStatus};

    fn test_store() -> Rc<HistoryStore> {
        let dir = std::env::temp_dir().join(format!(
            "trv-conv-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        Rc::new(
            HistoryStore::open_with_iterations(&dir, "conv-pass", 1000).expect("store"),
        )
    }

    fn seed_peer(store: &HistoryStore, peer: [u8; 32], texts: &[&str]) {
        for (i, t) in texts.iter().enumerate() {
            let mut id = [0u8; 16];
            id[0] = i as u8;
            id[1] = peer[0];
            store
                .append(&HistoryMessage {
                    id,
                    peer,
                    outgoing: i % 2 == 0,
                    status: HistoryStatus::Delivered,
                    timestamp: i as u64,
                    text: t.to_string(),
                })
                .expect("append");
        }
    }

    #[test]
    fn list_shows_peers_with_previews() {
        let store = test_store();
        let p1 = [1u8; 32];
        let p2 = [2u8; 32];
        seed_peer(&store, p1, &["hello there"]);
        seed_peer(&store, p2, &["first", "second message"]);
        let mut handles = HashMap::new();
        handles.insert(p1, "alice".to_string());
        let s = ConversationsScreen::new(Rc::clone(&store), handles, None, 640, 400);
        assert_eq!(s.row_count(), 2);
        let mut out = String::new();
        s.draw_text(&mut out, 60, 24);
        assert!(out.contains("alice"));
        assert!(out.contains("second message"));
        // Unknown handle falls back to truncated key.
        assert!(out.contains("0202"));
    }

    #[test]
    fn unread_counts_and_mark_seen() {
        let store = test_store();
        let p1 = [9u8; 32];
        seed_peer(&store, p1, &["a", "b", "c"]);
        let mut s = ConversationsScreen::new(Rc::clone(&store), HashMap::new(), None, 640, 400);
        assert_eq!(s.unread_for(&p1), 3);
        s.mark_seen(&p1);
        assert_eq!(s.unread_for(&p1), 0);
        // New message after seen → unread again.
        seed_peer(&store, p1, &["d"]);
        s.refresh();
        assert_eq!(s.unread_for(&p1), 1);
    }

    #[test]
    fn enter_opens_selected_peer() {
        let store = test_store();
        let p1 = [7u8; 32];
        seed_peer(&store, p1, &["hi"]);
        let mut s = ConversationsScreen::new(Rc::clone(&store), HashMap::new(), None, 640, 400);
        assert!(s.take_open().is_none());
        s.on_event(UiEvent::Enter);
        assert_eq!(s.take_open(), Some(p1));
        assert!(s.take_open().is_none()); // consumed
    }

    #[test]
    fn escape_requests_back() {
        let store = test_store();
        let mut s = ConversationsScreen::new(Rc::clone(&store), HashMap::new(), None, 640, 400);
        assert!(!s.take_back());
        s.on_event(UiEvent::Escape);
        assert!(s.take_back());
    }

    #[test]
    fn scroll_moves_selection() {
        let store = test_store();
        seed_peer(&store, [1u8; 32], &["a"]);
        seed_peer(&store, [2u8; 32], &["b"]);
        let mut s = ConversationsScreen::new(Rc::clone(&store), HashMap::new(), None, 640, 400);
        let first = s.selected;
        s.on_event(UiEvent::Scroll(-1));
        assert_ne!(s.selected, first);
        s.on_event(UiEvent::Scroll(1));
        assert_eq!(s.selected, first);
    }

    #[test]
    fn empty_list_renders() {
        let store = test_store();
        let s = ConversationsScreen::new(Rc::clone(&store), HashMap::new(), None, 640, 400);
        assert_eq!(s.row_count(), 0);
        let mut out = String::new();
        s.draw_text(&mut out, 60, 24);
        assert!(out.contains("No conversations"));
        let mut fb = vec![0u32; 320 * 200];
        s.draw(&mut fb, 320, 200);
        assert!(fb.iter().any(|&p| p != 0));
    }

    #[test]
    fn draw_paints_framebuffer() {
        let store = test_store();
        seed_peer(&store, [3u8; 32], &["paint me"]);
        let s = ConversationsScreen::new(Rc::clone(&store), HashMap::new(), None, 320, 200);
        let mut fb = vec![0u32; 320 * 200];
        s.draw(&mut fb, 320, 200);
        let painted = fb.iter().filter(|&&p| p != 0).count();
        assert!(painted > 500, "expected painted pixels, got {painted}");
    }
}
