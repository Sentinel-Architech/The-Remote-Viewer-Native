//! Local-first key/value store.
//!
//! SQLite-ready: swap the in-memory map for `rusqlite` (MIT/Apache-2.0)
//! later behind this same API. Everything stays on-device.

use std::collections::HashMap;

/// On-device store. No sync, no cloud.
#[derive(Debug, Default)]
pub struct LocalStore {
    kv: HashMap<String, Vec<u8>>,
}

impl LocalStore {
    /// Create an empty on-device store.
    pub fn new() -> Self {
        LocalStore {
            kv: HashMap::new(),
        }
    }

    /// Store `value` under `key`, overwriting any previous entry.
    pub fn put(&mut self, key: &str, value: Vec<u8>) {
        self.kv.insert(key.to_string(), value);
    }

    /// Fetch the bytes stored under `key`, or `None` if absent.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.kv.get(key).map(|v| v.as_slice())
    }

    /// Remove the entry under `key`, if present.
    pub fn delete(&mut self, key: &str) {
        self.kv.remove(key);
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.kv.len()
    }

    /// True when no entries are stored.
    pub fn is_empty(&self) -> bool {
        self.kv.is_empty()
    }
}
