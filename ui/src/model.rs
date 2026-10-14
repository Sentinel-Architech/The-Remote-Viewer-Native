//! Chat session model: messages + input buffer. Pure logic, no I/O.
//!
//! `ChatSession` owns a [`Sentinel`](trv_core::sentinel::Sentinel); every
//! submitted line is answered on-device through the MoE router. Nothing
//! here touches the network, by construction: the only dependency is
//! `trv-core`, which itself performs no I/O.

use trv_core::sentinel::Sentinel;

/// Who said a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Author {
    /// The device owner.
    You,
    /// The on-device Sentinel.
    Sentinel,
}

/// One chat line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub author: Author,
    pub text: String,
}

impl Message {
    pub fn new(author: Author, text: impl Into<String>) -> Self {
        Message {
            author,
            text: text.into(),
        }
    }
}

/// The conversation state behind the Sentinel chat screen.
#[derive(Debug)]
pub struct ChatSession {
    sentinel: Sentinel,
    messages: Vec<Message>,
    input: String,
    /// Maximum messages retained (oldest are dropped).
    capacity: usize,
}

impl ChatSession {
    /// Start a session bound to the owner's handle. Seeds one greeting
    /// from the Sentinel so the screen is never empty.
    pub fn new(owner_handle: &str) -> Self {
        let sentinel = Sentinel::new(owner_handle);
        let mut s = ChatSession {
            sentinel,
            messages: Vec::new(),
            input: String::new(),
            capacity: 200,
        };
        s.push(Author::Sentinel, "Sentinel online. On-device only - ask me anything.");
        s
    }

    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    pub fn input(&self) -> &str {
        &self.input
    }

    /// Current input, for tests/backends that manage their own buffer.
    pub fn push_input(&mut self, c: char) {
        self.input.push(c);
    }

    pub fn pop_input(&mut self) {
        self.input.pop();
    }

    pub fn clear_input(&mut self) {
        self.input.clear();
    }

    /// Submit the current input line: appends the user's message, then the
    /// Sentinel's on-device answer. Returns `false` when the input was
    /// empty (nothing submitted).
    pub fn submit(&mut self) -> bool {
        let text: String = self.input.drain(..).collect();
        let text = text.trim().to_string();
        if text.is_empty() {
            return false;
        }
        self.push(Author::You, text.clone());
        let answer = self.sentinel.ask(&text);
        self.push(Author::Sentinel, answer);
        true
    }

    fn push(&mut self, author: Author, text: impl Into<String>) {
        if self.messages.len() >= self.capacity {
            self.messages.remove(0);
        }
        self.messages.push(Message::new(author, text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_seeds_greeting() {
        let s = ChatSession::new("viewer");
        assert_eq!(s.messages().len(), 1);
        assert_eq!(s.messages()[0].author, Author::Sentinel);
    }

    #[test]
    fn submit_routes_through_sentinel() {
        let mut s = ChatSession::new("viewer");
        s.push_input('h');
        s.push_input('i');
        assert!(s.submit());
        assert_eq!(s.messages().len(), 3);
        assert_eq!(s.messages()[1].author, Author::You);
        assert_eq!(s.messages()[1].text, "hi");
        assert_eq!(s.messages()[2].author, Author::Sentinel);
        assert!(s.messages()[2].text.contains("viewer"));
        assert!(s.input().is_empty());
    }

    #[test]
    fn empty_submit_is_noop() {
        let mut s = ChatSession::new("viewer");
        assert!(!s.submit());
        assert_eq!(s.messages().len(), 1);
    }

    #[test]
    fn backspace_edits_input() {
        let mut s = ChatSession::new("viewer");
        s.push_input('a');
        s.push_input('b');
        s.pop_input();
        assert_eq!(s.input(), "a");
    }

    #[test]
    fn capacity_drops_oldest() {
        let mut s = ChatSession::new("viewer");
        s.capacity = 3;
        s.push(Author::You, "one");
        s.push(Author::You, "two");
        s.push(Author::You, "three");
        assert_eq!(s.messages().len(), 3);
        assert_eq!(s.messages()[0].text, "one");
        s.push(Author::You, "four");
        assert_eq!(s.messages()[0].text, "two");
    }
}
