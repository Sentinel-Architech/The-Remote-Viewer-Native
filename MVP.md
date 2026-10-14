# The Remote Viewer Network Native — 12-Month MVP Plan
*Drafted 2026-10-13. Local document only — not pushed to GitHub.*

## Why this plan exists

The goal is a shippable product that can take money within one year. This plan is
built to maximize that shot. It does not promise revenue — no one honestly can.
What it does is cut everything that isn't required to charge, sequence what's left,
and name every honest blocker in plain language.

## The product that can charge

The tightest shippable paid product is:

1. **A native Pixel app that installs with one tap** — no terminal, per your rule.
2. **Registration** — `Username@RV.com` identity, Male/Female selection, State-ID
   eligibility rule, human verification for paid tiers.
3. **The Sentinel** — text-first at MVP (voice later), routing live through the
   on-device MoE router across all 11 expert skills.
4. **Interactive Gateway** — the full guided session, on-device.
5. **Tier subscriptions with on-device entitlement gating** — Free (ghost / "low
   lights"), Monthly, Yearly, Founding. Paywalls enforced in-app.
6. **A persistent TRV wallet** — balances that survive restarts, transfer-fee
   policy applied.

Everything else — Solana token rails, AR geolocation earning, creator
marketplace, NFT minting, unlimited call/text/video, voice-first Sentinel — is
real, and it comes after the product can charge. Sequencing is the strategy.

## Where we stand today

Already built locally in `~/workspace/native-core-draft/` (78 tests passing,
zero warnings, clippy clean, zero external dependencies, MIT-only, no network):

| Module | Status |
|---|---|
| `trv-core`: crypto (FNV-1a integrity), identity (`Username@RV.com`, State-ID eligibility), qr (reverse-inverted scramble + tamper detection), airgap (CRC-16-CCITT, TRVL1 encode/decode), moe (11-skill router), sentinel (`ask()` routes via MoE), gateway (interactive session state machine, educational), osint (educational structures), wallet (state machine, 50 bps fee quote), hw (traits, stubs), sharing (mutual-follow NFC gate) | Logic done, tested |
| `trv-backend`: store (local store), profile (profile vault), subscriptions (tiers, discount categories, verification statuses, entitlement gating) | Logic done, tested |
| `sentinel-cli` binary | Working, smoke-tested |

Full spec in `~/workspace/The-Remote-Viewer-Native-SPEC.md`; monetization detail in
`~/workspace/MONETIZATION.md`.

## The four hard blockers (read these first)

These are the things that decide whether money is possible within a year. None
of them are code-quality problems — they're structural.

1. **No build host.** You have no laptop or desktop — only Pixel phones.
   A releasable Android app (APK) and any Solana program both need a Linux
   build machine. Pixel/Termux is not a Solana build host, and Android NDK
   cross-compilation from a phone is not a realistic path. A cheap VPS
   (~$5–10/mo) or a used laptop is the single most important unblocking
   investment. Everything in this plan assumes one is obtained in Month 1.
2. **No UI shell.** The core is a library. There is no screen yet — no app,
   no installer, no one-tap anything. Building a truly native Android UI in
   pure Rust with zero corporate SDKs is the biggest engineering lift in the
   plan. This is where outside help (a native mobile developer) would buy the
   most time.
3. **No payment rail.** The entitlement logic knows *who should pay*; nothing
   collects money. Google Play billing is off the table (corporate, violates
   your constraint). The two honest options: (a) **manual activation** — you
   sell Founding Member subscriptions directly (e.g., via your X,
   @TRV_Architech) and the app unlocks via an activation code you issue;
   (b) **Solana TRV-token subscriptions** — fully native, but needs an
   audited on-chain program plus a build host (blocker #1). Year 1 revenue
   almost certainly comes through (a).
4. **Voice is not MVP.** A voice-first Sentinel with on-device inference
   cannot be built in pure std Rust — it needs an on-device speech model and
   runtime. The MVP Sentinel is text-first with the full MoE router live;
   permission-gated sensor hooks are designed now, wired later.

## Phase plan

### Phase 1 — "Own the device" (Months 1–3)
*Goal: a real app on your Pixel that installs with one tap.*

**Concrete deliverables:**
- Rust core compiling for `aarch64-linux-android`; minimal native UI shell:
  first-run registration screen, Sentinel chat screen (text), Gateway session
  screen. Screen-agnostic core, one thin Android shell.
- Signed APK published as a GitHub release; one-tap install flow documented
  (GrapheneOS permits direct APK install — no Play Store, no terminal).
- Registration: `Username@RV.com` identity creation, Male/Female selection,
  State-ID eligibility capture; Free tier active by default (ghost mode, ~1
  mile comms rule, "low lights" research).
- Wallet state persisted on-device (SQLite wiring of `store.rs`).

**Already built:** all core/backend logic, Sentinel CLI proving the router.
**Must build:** Android target config, UI shell, APK signing + release flow,
  SQLite persistence, registration screens.
**Blockers:** build host (blocker #1); UI engineering capacity (blocker #2).
**Revenue relevance:** none yet — but nothing can charge until this exists.

### Phase 2 — "Charge for it" (Months 4–6)
*Goal: the first dollar. Manual rails, honest and working.*

**Concrete deliverables:**
- Entitlement enforcement across the app: paid tiers unlock full Sentinel
  (unlimited, no meter), full Gateway, full research; Free stays ghost/"low
  lights". This is the paywall, wired to the existing `unlimited_entitlement`
  logic.
- Manual activation codes: you issue a code per paying Founding Member;
  the app verifies it on-device (signed with your key — design this in
  Phase 1). No corporate payment processor involved, ever.
- Tier pricing decided 2026-10-13 and published: Tier 1 — $10/month or $100/year; Tier 2 — $25/month or $150/year; Tier 3 — $45/month or $200/year.
- Discount decided 2026-10-13: 20% off yearly for Education / Authority / ServeProtect (changeable); 17.67% off yearly for American citizens (whether it stacks with the 20% is TBD).
- Weekly-reset semantics after 3 months of recurring monthly decided and
  implemented, or explicitly deferred.

**Already built:** tiers, discount categories, verification statuses,
  entitlement gating logic, wallet state machine.
**Must build:** paywall wiring, activation-code scheme, pricing/discount
  decisions, terms a buyer can read.
**Blockers:** your pricing decisions (see below); a channel to sell through —
  your X (@TRV_Architech) is the natural one.
**Revenue relevance:** HIGH. This is the most likely first revenue in the
  plan — direct Founding Member subscriptions, sold by you, activated in-app.

### Phase 3 — "The Sentinel lives" (Months 7–9)
*Goal: the product becomes worth renewing.*

**Concrete deliverables:**
- Sentinel upgrades: conversation memory per owner (on-device), all 11
  expert skills meaningfully answering (not just routing), permission-gated
  sensor hooks designed and documented (explicit, revocable — your rule).
- The two Sentinel educational simulation games from your GitHub located and
  ported to native — the only simulation in the DApp, per your spec.
- OSINT educational modules completed; Gateway content deepened.
- E2E QR identity sharing via camera; mutual-follow NFC sharing wired to
  real platform NFC (currently gated logic only).

**Already built:** MoE router, Sentinel `ask()`, Gateway state machine,
  OSINT structures, QR scramble, sharing gate logic.
**Must build:** on-device conversation memory, skill depth, Android sensor
  bindings, game ports, NFC/camera platform bindings.
**Blockers:** the two GH games are still unlocated — finding them is a
  Month-7 task; sensor bindings need the native UI shell mature.
**Revenue relevance:** retention — this is what turns a first payment into a
  second.

### Phase 4 — "Token rails" (Months 10–12)
*Goal: TRV token economics go live for those who want them.*

**Concrete deliverables:**
- Solana program for TRV token/governance built on the external build host,
  audited, deployed — Solana stays scoped to token/governance only, per your
  split. Everything else remains on-device.
- Wallet connects to on-chain balances; outbound platform transfer-fee
  settles (fee: 25% to TRV — decided 2026-10-13; the 50 bps code placeholder is being replaced).
- Highest-tier gas-fee-waiver NFT minting (4 per top-tier member), creator
  watermarking groundwork.
- AR geolocation earning scoped honestly: adult, no cartoon animation,
  anti-spoofing design.

**Already built:** wallet state machine, fee-quote logic, tokenomics notes.
**Must build:** nearly all of it — program, audit, deployment, bridge logic.
**Blockers:** audit cost and auditor availability; mainnet risk; build host
  (blocker #1 again). If the audit isn't fundable, this phase slips and the
  manual rails from Phase 2 carry the revenue — the plan survives that.
**Revenue relevance:** scale — token economy and creator 80% payouts unlock
  here, but only if the audit path clears.

## Go-to-market sequence

*Approved 2026-10-13.* This is the order things launch in — what pulls people
in, what keeps them, and what spins out later. Nothing here is sellable
standalone today (no UI shell yet); this is the sequence for when the shell
exists.

- **Phase A — Draw:** The Sentinel (private, on-device, never phones home)
  plus the unbiased, source-cited news feed launch first. These are the hooks
  that pull users into The Remote Viewer Network.
- **Phase B — Keep:** Creator economics become the retention loop — 80% to
  exclusive creators, special badges, irreplaceable watermarks. If creators
  can earn a living here, they stay, and they bring their audiences with
  them. Creators are the growth engine.
- **Phase C — Expand:** Standalone spin-outs later, only once the Network has
  users — e.g., a standalone Sentinel app, a standalone news app. Launched
  from a position of strength, not as a first bet.

## What maximizes the shot

- **Ship Phase 1 small.** Every week spent polishing non-revenue features is a
  week not selling.
- **Sell manually in Phase 2.** You, your X account, Founding Member
  subscriptions, activation codes. Unfashionable, zero-corporate, and it works.
- **Decide the open pricing questions early** — tier prices, the 20% discount, the 17.67% American-citizen discount, and the 25% TRV transfer fee are now decided (below); the remaining open items no longer block Phase 4's fee logic, only its funding/audit.
- **Keep the daily 6am progress check** — small, steady, visible progress is
  how a one-person project with no laptop stays on track.

## Decisions only you can make

1. Tier prices and discount percentages (Education / Authority / ServeProtect; American citizens) — **decided 2026-10-13**: Tier 1 $10/mo or $100/yr; Tier 2 $25/mo or $150/yr; Tier 3 $45/mo or $200/yr; 20% off yearly (changeable); 17.67% off yearly for American citizens (stacking with 20% is TBD).
2. The outbound TRV transfer-fee amount — **decided 2026-10-13: 25% to TRV** when relocating TRV tokens to an outside wallet (50 bps code placeholder being replaced).
3. Founding Member terms — and reconciling "manual GitHub install" with
   "no one should NEED a terminal."
4. Weekly-reset semantics after 3 months of recurring monthly.
5. Whether the Solana audit is funded in year 1, or Phase 4 slips.
6. Token pool confirmation (80/10/10 from GH TOKENOMICS vs 95/5 and 90/10 in
   `solana/PROGRAM.md`).

## What this plan will not promise

- It will not promise revenue. It builds the shortest honest path to *being
  able to charge* and names what has to go right.
- It will not claim compliance (federal/HIPAA/ADA), audited cryptography, or
  mainnet readiness before independent review exists.
- Stubs are labeled as stubs. The transfer-fee amount was decided 2026-10-13
  (25% to TRV; 50 bps code placeholder being replaced); tier prices and discount rates were
  decided 2026-10-13; weekly-reset accounting is still a placeholder.

---
*End of MVP plan. Next step when you're ready: lock the Phase 2 pricing
decisions and the build-host question — those two unblock everything else.*
