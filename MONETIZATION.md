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
- **AR exploration** (decided 2026-10-13): Remote Viewers gain TRV crypto dust (small amounts) when they explore nature and find new areas. (Note: "dust" here means small rewards — distinct from the anti-cashout dust rule below.) (Policy only; no AR exploration mechanism implemented.)
- **AR anti-cashout** (decided 2026-10-13): AR-earned TRV becomes dust if moved to an outside wallet. AR tokens are spendable in-Network only (customization, purchases) — they cannot be cashed out.
- **AR respectful bonus** (decided 2026-10-13): viewers earn MORE TRV when their Sentinel politely warns them they may be heading toward private property, as long as there are no recent crimes in that area. (Policy only; no AR mechanism implemented.)
- **External spend fee** (decided 2026-10-13): spending TRV coin elsewhere incurs a 20% fee. This is separate from the 25% transfer fee. Staking is free regardless of how much or how little is staked; staking for 90 days wipes out the 20% fee entirely for the duration of the stake. (Policy only; no fee collection or staking mechanism implemented.)
- **Staking rewards** (decided 2026-10-13): the more TRV staked, the more earned (proportional rewards; specific rates TBD). **Staking lock**: taking out stake beforehand is PROHIBITED — 90-day lock, no early unstaking. (Policy only; no staking mechanism implemented.)
- **Staking APY tiers** (from early drafts, decided 2026-10-13): 5% (100-999 TRV) / 8% (1K-9,999) / 12% (10K-99,999) / 15% (100K+). Duration multipliers: 1.0x (1mo) / 1.1x (3mo) / 1.25x (6mo) / 1.5x (12mo) / 2.0x (24mo). Per-tier daily reward caps apply. Governance: 1 TRV = 1 vote, 1,000 TRV to create proposals. **Anti-sybil protection**: detection of rapid account creation, reward-claim farming, connection farming, and voting manipulation — with risk scores, rate limits, and cooldowns. **NOTE**: the old drafts allowed DEX trading / cross-platform value transfer; this CONFLICTS with the AR anti-cashout dust rule (decided 2026-10-13) — the anti-cashout rule stands as the newer decision. (Policy only; no staking mechanism implemented.)

**AR token earning** (not implemented): geolocated TRV tokens earned like an adult Pokémon Go (no cartoon animation), stored in the TRV-native wallet. Anti-spoofing, geolocation-proof, and wallet persistence are undefined.

**Gas-fee-waiver NFTs** (not implemented): highest paid tiers receive 4 free gas-fee-waiver minted NFTs to sell. Minting, waiver mechanics, and marketplace logic do not exist yet.

**Token pool** (from GH TOKENOMICS — to confirm): digital/NFT primary split of 80% creator, 10% pool, 10% platform. Pool mechanics are not implemented in Native.

## 3. Creator Economics

- **80% to exclusive creators**: Remote Viewers who create exclusively for TRV keep 80% of what they sell. (Recorded as policy; no sales pipeline implemented.)
- **Creator paywalls** (confirmed 2026-10-13): creators can paywall their own content. Revenue split: **80% to creator, 20% to TRV**.
- **Adult content** (decided 2026-10-13): if two adults are consenting and it's XXX, it goes behind a paywall for a fee of the creator's choice, with 15% going to TRV Network for NFT costs. (Exception to the standard 80/20 creator split — adult XXX uses 85/15. Policy only; no implementation.)
- **Watermarks**: creators get watermarks that cannot be replaced. (Policy only; no implementation.)
- **Live customization**: Myspace-style account customization with music, but ENHANCED — creator profiles drive this. (Not implemented.)
- **NFT external sales** (decided 2026-10-13): NFTs can be sold outside TRV for a 20% fee to TRV. (Policy only; no marketplace or settlement implemented.)
- **Artist NFT flow** (decided 2026-10-13): an artist can take a picture with the TRV camera, use TRV art skills to create a one-of-a-kind NFT incorporating the picture, and sell it. Artists are rewarded in small ways for keeping content exclusively on TRV (specific rewards TBD; policy only).

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
