//! trv-backend: local-first Hub replacement in Rust.
//!
//! No Node. No network. SQLite-ready (rusqlite wiring later —
//! MIT/Apache-2.0); in-memory stub for now.

pub mod activation;
pub mod ads;
pub mod badges;
pub mod entitlement;
pub mod gates;
pub mod paywall;
pub mod profile;
pub mod registration;
pub mod store;
pub mod subscriptions;
pub mod throttle;
pub mod verification;
