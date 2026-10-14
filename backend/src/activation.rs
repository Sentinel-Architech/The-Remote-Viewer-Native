//! Activation-code facade for the backend.
//!
//! The real protocol lives in [`trv_core::activation`]: Ed25519-signed
//! codes (issuer private key off-device, buyer embeds only the public
//! key), with a file-backed redemption registry. This module is a thin
//! re-export layer so backend code has a stable import path.
//!
//! The old TRV1 shared-secret scheme and the memory-only `CodeRegistry`
//! are removed. See `trv_core::activation` docs for the protocol and
//! the fail-closed corruption policy.

pub use trv_core::activation::{
    default_registry_path, mint, verify, ActivationError, Claims, FileCodeRegistry, PaidTier,
};
