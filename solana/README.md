# TRV Solana Programs

On-chain home of the TRV token: fixed-supply mint, transfer hook, and
90-day staking. This directory is a **standalone crate** (`trv-solana`)
— it is intentionally *not* a member of the parent Cargo workspace, so
`cargo` in the repo root never touches it.

> **Status: scaffold.** The full business logic is implemented and
> tested as pure Rust (34 tests, offline, std-only). It is **not
> deployed** — there is no Solana toolchain or funded keypair on this
> machine. The deploy checklist below is the exact path to mainnet.

## Design

All amounts are **base units** (`u64`); 1 TRV = 10^9 base units
(9 decimals, the Solana convention). Fee math runs through `u128`
intermediates: a wrapped fee would silently undercharge TRV, so
overflow is a hard error, never a wrap.

### 1. Token mint (`src/token.rs`)

* **Fixed supply:** 1,000,000,000 TRV (`TRV_TOTAL_SUPPLY`), set once.
* `initialize_mint` creates the mint with zero supply.
* `mint_to` requires the mint authority's signature and fails closed
  if the mint would exceed the cap.
* The cap **auto-locks** when reached, and the authority can also
  `lock_supply` early. Locking is **irreversible** — no inflation
  path exists afterwards.

### 2. Transfer hook (`src/transfer_hook.rs`)

Enforces the two money rules on every transfer of the TRV mint
(designed as a Token-2022 transfer hook on-chain):

| Transfer | Rule |
|---|---|
| Network → Network | Fee-free |
| Network → **Outside** wallet | **25% fee** to the TRV treasury |
| AR-earned → Outside wallet | **Burned to dust** (soulbound; nets zero) |
| AR-earned → Network | Allowed, fee-free |

The 25% fee matches `trv_core::wallet::TRANSFER_FEE_BPS` (2500 bps).
Dust amounts round down — a fee of less than 1 base unit is 0.

### 3. Staking (`src/staking.rs`)

* **Free** to enter, any amount ≥ 1 base unit, one stake per wallet.
* **90-day lock** (`STAKE_LOCK_SECS = 7,776,000`). **No early
  unstake** — not partial, not with penalty, not at all.
* **Proportional rewards:** linear accrual at `REWARD_RATE_BPS_PER_LOCK`
  per full lock (placeholder 5%; real rate TBD at program init).
  Rewards do not compound and are paid once per lock.
* **External-spend fee waiver:** unstaked wallets pay a 20% fee
  spending TRV outside the Network; wallets with an active stake pay
  **0%** for the duration of the stake (`external_spend_fee_bps`).

### 4. Program skeleton (`src/program.rs`)

Anchor-style structure with **zero dependencies**: an `Instruction`
enum, explicit `Accounts` bundle, and a pure `process_instruction`
dispatcher. Time is injected as a `now` parameter (never read from a
clock inside the logic); signatures are explicit `is_signer` flags.
The deploy step wraps this in a thin Anchor adapter (mapping table in
the module docs).

## Test

```sh
cd solana
cargo test --offline
```

34 tests, all offline: fee math, mint cap/lock/authority, the full
transfer policy matrix, staking lock enforcement (including
one-second-early rejection), reward proportionality, the fee waiver,
and double-claim/double-unstake protection.

## Deploy checklist (not yet done)

- [ ] **1. Toolchain.** Install the Solana CLI and Anchor (`avm`):
      `sh -c "$(curl -sSfL https://release.solana.com/stable/install)"`
      and `cargo install --git https://github.com/coral-xyz/anchor avm`.
- [ ] **2. Keypair & funds.** `solana-keygen new -o deployer.json`;
      fund it (devnet airdrop for testing; real SOL for mainnet).
- [ ] **3. Anchor project.** `anchor init trv-token --no-git`; copy
      `src/*.rs` logic into `programs/trv-token/src/`, add
      `anchor-lang` + `anchor-spl` deps, and write the thin adapter:
      `#[program]` → `process_instruction`, `#[derive(Accounts)]` →
      `Accounts`, `#[account]` → the `*Record` structs,
      `Clock::get().unix_timestamp` → the `now` parameter.
- [ ] **4. Transfer hook.** Implement as a Token-2022 transfer hook
      program referencing this mint; test on devnet with the SPL
      Token-2022 program.
- [ ] **5. Program ID.** Replace `PROGRAM_ID` in `src/program.rs`
      with the real address (`anchor keys list`), redeploy.
- [ ] **6. Devnet rehearsal.** `anchor build && anchor test`;
      initialize mint, mint a test supply, run transfers through the
      hook, stake/unstake a full 90-day cycle on a local validator
      with warped time.
- [ ] **7. Treasury.** Set the real treasury pubkey (replaces
      `TREASURY_PLACEHOLDER`); verify fees land there.
- [ ] **8. Reward rate.** Set the final `REWARD_RATE_BPS_PER_LOCK`
      (currently a 5% placeholder — user decision pending).
- [ ] **9. Audit.** Independent audit of the on-chain code before
      mainnet (same bar as the handwritten crypto in `core`).
- [ ] **10. Mainnet deploy.** `anchor deploy --provider.cluster mainnet`;
      `lock_supply` once the intended circulating supply is minted;
      publish the program ID and treasury address.

## What this scaffold deliberately does NOT do

* No network I/O, no RPC calls, no wallet signing — custody stays
  with the user (self-custody policy).
* No Anchor/Solana SDK dependency — the logic must stay testable
  offline on this machine.
* No changes to the parent workspace (`Cargo.toml` untouched).
