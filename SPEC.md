# The Remote Viewer Network — Native SPEC
**100% Native Stack, Open Source — Draft for Review**
*Generated 2026-10-13 from user's spec. Not pushed to GH without approval.*

## 1. Vision
- Hybrid of all social media that are WANTED and LOVED, with NONE that are HATED.
- Neural linguistics to help CONNECT HUMANITY IN REAL LIFE.
- NO big centralized cloud. Local-first.
- Inspiration: Researching Epstein files + deep dive into the Gateway Process → epiphany.
- Include ALL aspects of The Gateway Process in Native/DApp. Must be interactive.
- OSINT included as well for educational reasons.
- AIMED at One Nation under God. God isn't to be forced upon, but subtly hinted at on religious days.
- If a practice is against Christianity, it is to be correctly guided with ZERO bias.
- Ideal icon: Eye with cosmic tunnel + hooded meditating figure ("PROTECTED ORIGINAL - COMMISSIONED WORK - EXCLUSIVE").

## 2. Build Principles — ZERO BLOAT, ZERO CORPORATE, ZERO BACKDOORS
- 100% native stack, 100% open-source only (MIT / Apache-2.0).
- Minimal dependencies. Nothing overlooked, best and smartest in all ways, enhanced.
- No corporate code. No known tech giants/entities. No Michigan Micro Mote line.
- EVERYTHING HAPPENS ON DEVICE and NEVER over cell towers to transmit data — except Solana parts (see §10).
- No outside services for NEWS, finances, medical records, or ANYTHING ELSE required by device. If it can be read or watched on a device, it's NATIVE.
- Every aspect of The Remote Viewer Network to be FEDERALLY COMPLIANT, including HIPAA and ADA compliant system-wide, and encrypted per individual Remote Viewer.
- User retains full ownership. No human may claim ownership because their AI helped create an aspect.
- Remote control is okay, but nothing like a KILL SWITCH unless a picture of something is taken (to be clarified).

## 3. Target Devices
- EVERY DEVICE WITH A SCREEN: wearable, fold, clam, laptop, desktop, hobbyist boards.
- Reference build: Pixel 7 with GrapheneOS (user's primary target).
- User currently chats from Pixel 6a (Muse app won't run on Pixel 7 GrapheneOS).
- Core is portable Rust, screen-agnostic. Thin native UI shells per form factor.

## 4. Native Architecture (to replace skeleton)
Current Native repo is a Rust workspace skeleton (`core`, `backend`). Proper rebuild:
- `core/` — crypto, E2E reverse-inverted scramble QR, optical air-gap (age + Soliton LT + QR), Ed25519 identity, self-heal, MoE router/gate.
- `backend/` — local-first Hub replacement in Rust (no Node): native auth, SQLite, profile vault, daily watch logic.
- `ui/` — truly native UI (egui/iced, not webview) + holographic-ui.
- `cli/` — Sentinel CLI in Rust.
- `edge/` — Termux helpers, ESP32 stubs, GrapheneOS verified.
- Explicitly out: Solana Track A scaffold stays separate (see §10), EVM contracts held, Expo/Vite legacy parked.

## 5. Mixture of Experts + The Sentinel (EI)
- On-device MoE to help each Remote Viewer learn/find on local device. No cloud.
- Main repo reference: `grok/router` + 11 skills: cognitive-science, coordinator, declassified-ops, first-aid, mathematics, physics, political-science, quantum, remote-viewer, simple-comms, zk.
- ONLY ONE EI in The Remote Viewer Network: **The Sentinel**.
  - Siri/Google equivalent: user speaks to their Sentinel, it learns exclusively about them, on-device.
  - Searches GLOBAL NET for any/all requests as long as DECLASSIFIED — then not off limits (We The People, 1st Amendment, FOIA).
  - Research rule: only NOT researched if NOT PUBLIC AND NOT ABOUT ME.
  - List of protections: to be defined (not found in GH yet — user to provide).
  - GH contains TWO simulation games that are also EDUCATIONAL FOR THE SENTINEL (to be ported to Native). These are to be the only simulation about this whole DApp.
  - Quality bar (decided 2026-10-13): both simulation games must be HIGH RESOLUTION, immersive, and relevant.
  - Game 1 "God's Eye" (decided 2026-10-13): as relevant as homeland security sees cyber threats.
  - Game 2 "Neural Mesh" (decided 2026-10-13; code name in GH: "neural-link"): matrix-themed through the brain, covering medical ailments to heal and protect the brain; all in-game education to be medically relevant to 2026. (Creative direction for the game, not a medical claim.)
  - Transitions (decided 2026-10-13): vortex animation for transitions into games, out of games, and between in-game events.
  - The Sentinel is to have the ability to use ALL SENSORS AND COMPONENTS of the Remote Viewer device.

## 6. Identity & Email
- Login via traditional email to verify they are real.
- Once registered, they get their own DECENTRALIZED encrypted email to replace traditional ones.
- Format: `Username@RV.com`.
- At registration they must select either Male or Female, NOTHING ELSE EVER.
- Background ID verification via state/fed ID to prove human (for unlimited tiers). NO PEDOPHILES ALLOWED.
- If Remote Viewer doesn't own a State ID then VERIFICATION is ineligible.

## 7. Communication & Sharing
- Each Remote Viewer gets E2E reverse-inverted scramble encryption QR, shared only with chosen contacts via camera OR ~1 mile proximity.
- Not registered: 1 mile limit for all comms. Emergency = unlimited, no signal restrictions.
- NFC: allow anything to be shared via NFC, but ONLY if actually following each other on the Network.
- Customization: live account customization like Myspace (music etc.), but ENHANCED.
- Creators get watermarks that can't be replaced. Remote Viewers who want to earn a living creating exclusively for TRV get 80% of what they sell.
- Creator paywalls (confirmed 2026-10-13): creators can paywall their own content. Revenue split: 80% to creator, 20% to TRV.

## 8. Subscriptions, Tiers, Founding Members
- Tiers (decided 2026-10-13): Tier 1 — $10/month or $100/year; Tier 2 — $25/month or $150/year; Tier 3 — $45/month or $200/year.
- Discount: 20% off yearly for the Education system, authority, and all those who serve and protect every American and are paid to do it willingly (decided 2026-10-13; changeable).
- Discount: 17.67% off yearly subscriptions for American citizens (decided 2026-10-13). Whether this stacks with the 20% Education/Authority/ServeProtect discount is TBD — not assumed.
- Subscribed + human-verified: unlimited call/text/video.
- Unlimited enhanced intelligence once subscribed for at least one month: unlimited usage, no meter, no keys — because they own their device / own DApp if they built native stack via GH.
- Only other exceptions to unlimited: purchases of packs listed in GH.
- No monthly online OR yearly sub → no unlimited use. Weekly reset after 3 months of recurring monthly subscriptions.
- Highest paid tiers: 4 free gas-fee-waiver minted NFTs to sell.
- NFT external sales (decided 2026-10-13): NFTs can be sold outside TRV for a 20% fee to TRV.
- Artist NFT flow (decided 2026-10-13): an artist can take a picture with the TRV camera, use TRV art skills to create a one-of-a-kind NFT incorporating the picture, and sell it. Artists are rewarded in small ways for keeping content exclusively on TRV (specific rewards TBD).
- Founding Members: get 100% everything UNLIMITED if they've gone through GH to manually install (via dev mode terminal commands).
- Ads policy (decided 2026-10-13): Ghost tier gets native ads at 15 seconds per minute watched. No other tier gets ads. Native ads are served on-device, not via corporate ad networks.

## 9. Install — One Tap
- No one should NEED a terminal, not even the user themselves.
- One-tap install for everyone by default.
- (Note: earlier spec had terminal for dev mode to become Founding Member — conflicts with "no one NEEDS terminal", to be reconciled.)

## 10. Solana — REQUIRED (split)
- User requires Solana blockchain (overrides earlier no-blockchain).
- Constraint: no laptop/desktop, only phones. GH docs confirm Pixel/Termux ≠ Solana build host — needs external build host.
- Agreed split: Solana ONLY for TRV token/governance with network. Everything else strictly on-device.
- `trv_governance` in GH is scaffold/Track A, not proven, CI blocked, not audited, not mainnet. Proven path today is USDC+memo via `digital-vending/`.
- AR: like Pokemon Go for adults, NO cartoon animation. TRV tokens geolocated and earned into TRV-native crypto wallets, exclusive to TRV.
- **AR earnings** (decided 2026-10-13): TRV tokens gathered through AR are credited to the viewer's TRV wallet, spendable on profile customization and other Network purchases.
- **AR anti-cashout** (decided 2026-10-13): AR-earned TRV becomes dust if moved to an outside wallet. AR tokens are spendable in-Network only (customization, purchases) — they cannot be cashed out.
- No TRV tokens transferred to other platforms WITHOUT a transfer fee to TRV. (Transfer-fee amount: **25% to TRV — decided 2026-10-13.** The 50 bps placeholder in `core/src/wallet.rs` is being replaced with the decided 25%. TRV token intended as Solana blockchain crypto.)
- Each Remote Viewer gets their own digital wallet exclusive to TRV to add money or buy through TRV ecosystem.
- **Self-custody** (decided 2026-10-13): each Remote Viewer is 100% in charge of their own crypto wallet, which is exclusively TRV — TRV never takes custody.
- Native camera required for AR, same with phone, GPS, text and everything else a phone uses to communicate — all native.

## 11. Safety — HYDRA
- HYDRA PROTOCOL // SENTINEL OS: safety reporting for serious harms.
- Censored outbound packet; original seal stays on-device in local M-o-E; per-region emergency numbers.
- Reference: `apps/hub/src/lib/trv/hydra.ts` in main repo.

## 12. Token Pool (from GH TOKENOMICS, to confirm)
- Digital / NFT primary: 80% creator, 10% pool, 10% platform (per TOKENOMICS.md).
- $AR design-only, not launched, 0% corporate allocation.
- User to confirm pool behavior for Native.

## 13. Network Exclusivity
- Access, content, icon customization all exclusive to TRV NETWORK.
- If not PAID VERIFIED, user is essentially an anonymous ghost with no reach or signal.
- Anything researched through TRV without paid monthly subscription shows only low lights of everything in the DApp, with paywall for everything else until paid verified.

## 14. Content Policy
- Cannabis use is 100% permitted (decided 2026-10-13).

---
*End of draft. Review and tell me what to change before any GH push.*
