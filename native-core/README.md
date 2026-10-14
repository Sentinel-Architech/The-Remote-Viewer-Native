# The Remote Viewer — Native Core Draft

Minimal, compilable Rust workspace draft for `The-Remote-Viewer-Native`:
the 100% native, open-source rebuild of The Remote Viewer as a real DApp
(instead of the skeleton left behind).

## Members

### `core` (`trv-core`) — on-device primitives
- `crypto.rs` — device-local keypair stub, Ed25519-ready API.
- `identity.rs` — local identity, `Username@RV.com` decentralized email,
  State ID verification-eligibility rule (no State ID → ineligible).
- `qr.rs` — E2E reverse-inverted scramble QR stub.
- `airgap.rs` — TRVL1 frame / optical air-gap stubs.
- `moe.rs` — on-device Mixture-of-Experts router stub (all 11 expert
  skills: cognitive-science, coordinator, declassified-ops, first-aid,
  mathematics, physics, political-science, quantum, remote-viewer,
  simple-comms, zk).
- `sentinel.rs` — The Sentinel, the ONE Enhanced Intelligence:
  voice-first, learns exclusively about its owner on-device, declassified
  research rule only.
- `gateway.rs` — interactive Gateway Process: guided session
  (intro → 4 focus states → 6 concepts → reflection), prompts and local
  progress tracking. Educational only.
- `osint.rs` — educational OSINT study module. Local computation only.
- `wallet.rs` — TRV-exclusive digital wallet: add funds, buy TRV,
  within-network transfers, outbound transfer-fee policy
  (no TRV to other platforms without a fee to TRV).
- `hw.rs` — native hardware traits: camera (for AR), phone, GPS, text,
  proximity/NFC; in-process stub until real platform bindings plug in.

### `backend` (`trv-backend`) — local-first backend (no Node)
- `store.rs` — local-first store stub (SQLite-ready).
- `profile.rs` — encrypted profile vault stub.
- `subscriptions.rs` — tiers (Free/Monthly/Yearly/Founding), discount
  categories (Education, Authority, ServeProtect), State ID
  verification statuses, unlimited-entitlement gating. No network.

## Build principles
- **Native stack only.** No web wrappers, no corporate SDKs.
- **Zero bloat, zero corporate:** 100% open-source (MIT/Apache-2.0 only),
  minimal dependencies — currently zero external crates.
- **Everything on-device:** no network calls anywhere in this workspace.
- **Federally compliant**, including HIPAA and ADA compliance system-wide.
- **Encrypted per individual Remote Viewer.**
- **The user retains full ownership.** No human may claim ownership
  because their AI helped create an aspect.

## Explicitly out of this draft
- Solana code (separate track — TRV token/governance only).
- Real Ed25519/age/QR/GPS implementations (API-stable stubs; wire in
  MIT/Apache-2.0 crates later).
- Real Solana-side wallet/token transfer enforcement (policy constants
  are local placeholders).

## Status

Local draft only. **Nothing has been pushed to GitHub.**

Per-module status (as of this draft):

| Module | Crate | Status | Notes |
|---|---|---|---|
| `crypto.rs` | trv-core | **STUB** | API-stable keypair API, Ed25519-ready; real signing wired later. |
| `identity.rs` | trv-core | **FUNCTIONAL** | Local identity, `Username@RV.com` decentralized email, State ID verification-eligibility rule. |
| `qr.rs` | trv-core | **STUB** | E2E reverse-inverted scramble QR packet shape only. |
| `airgap.rs` | trv-core | **STUB** | TRVL1 frame / optical air-gap shape only. |
| `moe.rs` | trv-core | **FUNCTIONAL** | Keyword-based router (`route()`): all 11 expert skills covered, Coordinator fallback; model-weight gating lands later. |
| `sentinel.rs` | trv-core | **STUB** | Placeholder response; real on-device inference later. |
| `gateway.rs` | trv-core | **FUNCTIONAL** | Interactive Gateway Process session (intro → 4 focus states → 6 concepts → reflection) with prompts and local progress tracking. Educational only. |
| `osint.rs` | trv-core | **FUNCTIONAL** | Educational OSINT study lists (source types, concepts); no network I/O by design. |
| `wallet.rs` | trv-core | **FUNCTIONAL** | Local wallet state machine: add funds, buy TRV, transfers; outbound transfer-fee policy constants. No Solana code. |
| `hw.rs` | trv-core | **STUB** | Hardware capability traits + in-process stub implementation; real platform bindings plug in later. |
| `sharing.rs` | trv-core | **FUNCTIONAL** | NFC sharing gate: mutual-follow rule enforced, pure local computation, with unit tests. |
| `store.rs` | trv-backend | **STUB** | In-memory key/value store works locally; SQLite wiring (rusqlite) is a placeholder. |
| `profile.rs` | trv-backend | **STUB** | Profile fields + decentralized-email helper; no encryption yet (age wiring later). |
| `subscriptions.rs` | trv-backend | **FUNCTIONAL** | Tiers (Free/Monthly/Yearly/Founding), discount categories (Education, Authority, ServeProtect), State ID verification statuses, unlimited-entitlement gating. No network. |

## Build

The workspace intentionally has **zero external dependencies**
(`core` declares none; `backend` depends only on `trv-core` via path).
Builds and tests run fully offline:

```sh
cargo check --offline
cargo build --offline
cargo test --offline
```

All three must pass with zero warnings.
