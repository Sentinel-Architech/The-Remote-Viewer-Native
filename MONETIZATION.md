# The Remote Viewer Network — Native: Monetization Implementation Plan
*Drafted 2026-10-13. Local document only — not pushed to GitHub. No revenue is promised anywhere in this plan.*

## 1. Tier Subscriptions

**Tiers** (implemented as `Tier` in `backend/src/subscriptions.rs`; prices as `PaidTier` in the same module, decided 2026-10-13):
- **Free** — unregistered. All communication limited to ~1 mile. Emergency is the only unlimited exception. No unlimited use.
- **Monthly** — recurring monthly subscription. Unlimited call/text/video **only when** human-verified (`VerificationStatus::Verified`). Weekly reset of token pool after 3 months of recurring monthly subscriptions (spec'd, not yet implemented).
- **Yearly** — same unlimited entitlement as Monthly when verified.
- **Founding** — manually installed through GitHub (dev mode). 100% everything UNLIMITED.

**Decided pricing (2026-10-13):**
- Tier 1: $10/month or $100/year
- Tier 2: $25/month or $150/year
- Tier 3: $45/month or $200/year

**Verification gating** (implemented):
- `VerificationStatus`: Unverified / Pending / Verified / Ineligible.
- `check_verification(has_state_id)` returns **Ineligible** when the viewer has no State ID — per spec, verification is then ineligible.
- `unlimited_entitlement(tier, verification)` — the full on-device check. Monthly/Yearly require Verified; Founding is always unlimited; Free never is.
- Registration also requires selecting **Male or Female** (nothing else). Background state/federal ID verification is for unlimited tiers; NO PEDOPHILES ALLOWED is a stated safety rule.

**Discounts** (implemented as `DiscountCategory` in `backend/src/subscriptions.rs`):
- Education system, Authority, and those who serve and protect every American and are paid to do it willingly.
- **Decided 2026-10-13: 20% off yearly** for all three categories (changeable per the user).
- **Decided 2026-10-13: 17.67% off yearly subscriptions for American citizens.** Whether this stacks with the 20% category discount is TBD — not assumed.
- Discount flags exist for monthly and yearly; they apply to Monthly/Yearly tiers only.

**Network exclusivity**: Access, content, and icon customization are exclusive to the TRV Network. Not paid-verified = anonymous ghost with no reach or signal. Research without a paid subscription shows only "low lights" behind a paywall. (Policy; enforcement not implemented.)

**Ads policy** (decided 2026-10-13): Ghost tier gets native ads at 15 seconds per minute watched. No other tier gets ads. Native ads are served on-device, not via corporate ad networks. (Policy only; ad inventory, scheduling, and playback are not implemented.)

## 2. TRV Token Economics

**Wallet** (implemented in `core/src/wallet.rs` — local state machine only):
- Each Remote Viewer gets their own TRV-exclusive wallet: `Wallet` with funds balance and TRV token balance, on-device only.
- **Self-custody** (decided 2026-10-13): each Remote Viewer is 100% in charge of their own crypto wallet — TRV never takes custody. Wallets are exclusively TRV.
- Flows modeled: `add_funds`, `buy_trv` (stub conversion at a given rate), `send_within_network` (no fee), `transfer_to_platform` (deducts full amount, returns the TRV fee owed).
- **Transfer-fee policy** (implemented as constants): **25% to TRV when relocating TRV tokens to an outside wallet — decided 2026-10-13.**
- **Transfer-fee policy** (implemented as constants): **25% to TRV when relocating TRV tokens to an outside wallet — decided 2026-10-13.** TRV token intended as Solana blockchain crypto (aligns with the Solana-for-token plan). No TRV tokens move to another platform without this transfer fee to TRV. The quote computation is local; **no transfer actually settles anywhere** — settlement infrastructure does not exist yet. The previous 50 bps value was a code placeholder, not policy, and is being replaced with the decided 25%.
- **AR earnings** (decided 2026-10-13): TRV tokens gathered through AR are credited to the viewer's TRV wallet, spendable on profile customization and other Network purchases.
- **AR anti-cashout** (decided 2026-10-13): AR-earned TRV becomes dust if moved to an outside wallet. AR tokens are spendable in-Network only (customization, purchases) — they cannot be cashed out.

**AR token earning** (not implemented): geolocated TRV tokens earned like an adult Pokémon Go (no cartoon animation), stored in the TRV-native wallet. Anti-spoofing, geolocation-proof, and wallet persistence are undefined.

**Gas-fee-waiver NFTs** (not implemented): highest paid tiers receive 4 free gas-fee-waiver minted NFTs to sell. Minting, waiver mechanics, and marketplace logic do not exist yet.

**Token pool** (from GH TOKENOMICS — to confirm): digital/NFT primary split of 80% creator, 10% pool, 10% platform. Pool mechanics are not implemented in Native.

## 3. Creator Economics

- **80% to exclusive creators**: Remote Viewers who create exclusively for TRV keep 80% of what they sell. (Recorded as policy; no sales pipeline implemented.)
- **Creator paywalls** (confirmed 2026-10-13): creators can paywall their own content. Revenue split: **80% to creator, 20% to TRV**.
- **Watermarks**: creators get watermarks that cannot be replaced. (Policy only; no implementation.)
- **Live customization**: Myspace-style account customization with music, but ENHANCED — creator profiles drive this. (Not implemented.)

## 4. What's Built vs What's Not

**Implemented (local stubs, 66 tests passing, zero warnings, zero external deps):**
- `backend/src/subscriptions.rs` — tiers, discount categories, verification gating, entitlement checks.
- `core/src/wallet.rs` — wallet balances, buy/add flows, in-network send, platform-transfer fee quote.
- Tier entitlements are pure on-device logic; they do not charge anyone.

**Still needs building:**
- **Solana program** (`trv_governance` in the main GH repo is scaffold/Track A: not audited, not mainnet, CI blocked). Solana is the agreed split for token/governance network ops only; user has no laptop/desktop (Pixel 7/6a only), and Pixel/Termux is not a Solana build host, so an external Linux build host is required. Nothing here settles real value today.
- **Payment processing**: subscription checkout, recurring billing, discount verification (education/authority/serve-protect eligibility), weekly-reset accounting, and pack purchases from GH do not exist.
- **Transfer-fee settlement**: the fee is computed locally; there is no settlement, no custodian, no cross-platform bridge.
- **NFT minting** (gas-fee waivers) and **creator watermarking**.
- **Compliance**: federally compliant incl. HIPAA/ADA is a stated requirement; per-viewer encryption is a stated requirement. Neither is implemented or audited.

## 5. External Dependencies and Honest Caveats

- **Solana mainnet**: token economics depend on a built, audited, deployed Solana program. The current program is scaffold only. Until that happens, every token/economics feature is a local simulation.
- **User adoption**: subscription revenue requires verified, paying users; creator economics require buyers. No user base exists yet.
- **Compliance**: federal/HIPAA/ADA compliance claims are aspirational; no implementation or audit exists.
- **No revenue promised**: this plan builds the rails. Whether money flows through them is not something this document or the current code can guarantee.
