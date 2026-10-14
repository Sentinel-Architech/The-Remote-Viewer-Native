//! Ready-made backends. Each is a thin adapter between a real device and
//! the [`platform`](crate::platform) contract — the UI core itself never
//! changes when a backend is added.

pub mod terminal;
