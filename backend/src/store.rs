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

/// A namespaced view over a [`LocalStore`].
///
/// The underlying store is a flat key map shared by every backend
/// module (registrations, profiles, codes, ...). Without namespacing,
/// two modules that happen to pick the same key — e.g. both storing a
/// record under `"handle"` — silently overwrite each other. This
/// wrapper prepends `"{prefix}:"` to every key, so `"handle"` in the
/// `registration` namespace and `"handle"` in the `profile` namespace
/// land on different flat-map keys (`"registration:handle"` vs
/// `"profile:handle"`).
///
/// The prefix is an opaque byte string; it is stored in the key as-is.
/// Choose prefixes that cannot collide with raw keys (e.g. a module
/// name), and never read raw keys expecting namespaced ones.
#[derive(Debug)]
pub struct NamespacedStore<'a> {
    prefix: &'a str,
    store: &'a mut LocalStore,
}

impl<'a> NamespacedStore<'a> {
    /// Borrow `store` under `prefix`. Every get/put/delete on the
    /// returned view is namespaced by `prefix`.
    pub fn new(store: &'a mut LocalStore, prefix: &'a str) -> Self {
        NamespacedStore { prefix, store }
    }

    /// The flat-map key for `key`: `"{prefix}:{key}"`.
    fn namespaced(&self, key: &str) -> String {
        format!("{}:{key}", self.prefix)
    }

    /// Store `value` under `key` in this namespace, overwriting any
    /// previous entry in the same namespace.
    pub fn put(&mut self, key: &str, value: Vec<u8>) {
        self.store.put(&self.namespaced(key), value);
    }

    /// Fetch the bytes stored under `key` in this namespace.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.store.get(&self.namespaced(key))
    }

    /// Remove the entry under `key` in this namespace, if present.
    pub fn delete(&mut self, key: &str) {
        self.store.delete(&self.namespaced(key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_store_is_empty() {
        let store = LocalStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn put_get_roundtrip() {
        let mut store = LocalStore::new();
        store.put("k", b"value".to_vec());
        assert_eq!(store.get("k"), Some(b"value".as_slice()));
        assert_eq!(store.get("missing"), None);
    }

    #[test]
    fn put_overwrites() {
        let mut store = LocalStore::new();
        store.put("k", b"old".to_vec());
        store.put("k", b"new".to_vec());
        assert_eq!(store.get("k"), Some(b"new".as_slice()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn delete_removes() {
        let mut store = LocalStore::new();
        store.put("k", b"value".to_vec());
        store.delete("k");
        assert_eq!(store.get("k"), None);
        assert!(store.is_empty());
        // Deleting a missing key is a no-op.
        store.delete("missing");
        assert!(store.is_empty());
    }

    #[test]
    fn len_counts_entries() {
        let mut store = LocalStore::new();
        assert!(store.is_empty());
        store.put("a", vec![1]);
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
        store.put("b", vec![2]);
        assert_eq!(store.len(), 2);
        store.delete("a");
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }

    #[test]
    fn namespaces_do_not_collide() {
        let mut store = LocalStore::new();
        {
            let mut reg = NamespacedStore::new(&mut store, "registration");
            reg.put("handle", b"alice".to_vec());
        }
        {
            let mut prof = NamespacedStore::new(&mut store, "profile");
            prof.put("handle", b"alice-profile".to_vec());
        }
        // Same logical key, different namespaces: no overwrite.
        assert_eq!(store.get("registration:handle"), Some(b"alice".as_slice()));
        assert_eq!(store.get("profile:handle"), Some(b"alice-profile".as_slice()));
        // Raw logical key was never written.
        assert_eq!(store.get("handle"), None);
    }

    #[test]
    fn namespaced_get_put_delete_roundtrip() {
        let mut store = LocalStore::new();
        let mut ns = NamespacedStore::new(&mut store, "codes");
        ns.put("code1", b"TRV1-MO".to_vec());
        assert_eq!(ns.get("code1"), Some(b"TRV1-MO".as_slice()));
        assert_eq!(ns.get("code2"), None);
        ns.delete("code1");
        assert_eq!(ns.get("code1"), None);
    }
}
