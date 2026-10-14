# TRV Solana Deployment Plan

**Status (2026-10-14):** The VerificationRegistry program is converted to a real,
deployable Solana program. It compiles to SBF and is ready for devnet testing.
Nothing is deployed. No wallet exists. No SOL has been spent.

## What exists today

| Item | Location | State |
|---|---|---|
| Pure-Rust program logic (scaffold) | `solana/src/` | 107 tests passing, std-only, zero deps |
| Deployable identity program | `solana/programs/identity-registry/` | Builds to SBF (`trv_identity_registry.so`, ~26 KB), 6 adapter tests passing |
| Program keypair (unfunded) | `solana/programs/identity-registry/program-keypair.json` | Address: `EHbJGKAEUJLYq2BJ6Htj9aAZHKfwroA6VAonRdXL4USv`. Holds no SOL. |
| Toolchain | `~/workspace/solana-toolchain/` | solana-cli 4.3.0, cargo-build-sbf 4.3.0 — verified working |

**Not yet converted:** token economics, staking, referral, transfer hook,
anti-dump guard. They remain pure-Rust scaffolds. Each gets its own adapter
crate following the identity-registry pattern when the user is ready.

## Step-by-step: devnet first

### 1. Build (DONE — no user action needed)
```sh
export PATH="$HOME/workspace/solana-toolchain/solana-release/bin:$HOME/.cargo/bin:$PATH"
cd ~/workspace/native-core-draft/solana/programs/identity-registry
cargo build-sbf
# Output: target/deploy/trv_identity_registry.so
```

### 2. Create a deployment wallet (NEEDS THE USER)
The user must decide **who holds the keys**. Options:
- **A.** The user creates the wallet on their own device (most sovereign —
  matches the project's values, but they have only phones; a phone-based
  Solana wallet like Phantom/Backpack works).
- **B.** A temporary VM wallet for devnet testing only, replaced before mainnet.

```sh
solana-keygen new -o ~/.config/solana/id.json   # NEVER commit this file
solana config set --url devnet
solana airdrop 2                                 # devnet SOL is free
```

### 3. Deploy to devnet (after step 2)
```sh
solana program deploy \
  --program-id solana/programs/identity-registry/program-keypair.json \
  target/deploy/trv_identity_registry.so \
  --url devnet
```
Expected cost: ~0.5–1 devnet SOL (free via airdrop). Real cost on mainnet:
see below.

### 4. Test on devnet (after step 3)
- Derive the PDA for a test device key: seeds `[b"trv-attestation", device_key]`.
- Send a RegisterAttestation instruction (tag `0`, 106 bytes) with the device
  as signer.
- Read the PDA account back; confirm the 135-byte record decodes and
  `verification_status` reads `Verified`.
- Send RevokeAttestation (tag `1`, 33 bytes); confirm status reads `Revoked`.
- A small TypeScript or Rust client is needed for this — not yet written.

### 5. Mainnet (ONLY with explicit user approval)
Same as step 3 with `--url mainnet-beta` and real SOL. **Do not do this
until:** the program has been tested on devnet, the independent crypto review
is further along, and the user explicitly approves.

## Cost estimates (mainnet)

| Item | Approx. cost |
|---|---|
| Program deployment (26 KB binary) | ~1.5–2 SOL |
| PDA rent per attestation record (135 bytes, rent-exempt) | ~0.001 SOL each |
| Transaction fees | negligible (~0.000005 SOL/tx) |

At $200/SOL (illustrative, not a quote): deployment ≈ $300–400. The user
must fund the deployment wallet. **No funds exist today.**

## What the user must decide

1. **Devnet now?** Say the word and the next step is creating the deployment
   wallet (step 2). Nothing moves without this.
2. **Who holds the wallet keys?** Phone wallet (sovereign) vs. temporary VM
   wallet (convenient, less sovereign).
3. **Which programs next?** Token economics + staking are the natural next
   adapters after identity is proven on devnet.
4. **Mainnet timing?** Not recommended until devnet testing is complete and
   the crypto review has progressed. No rush — devnet is free.
5. **Program upgrade authority?** The deployer key can upgrade the program
   later. For mainnet, consider a multisig or governance-gated upgrade
   authority. Undecided.

## What CANNOT be done without the user

- Creating or funding any wallet (their keys, their money).
- Any devnet or mainnet deployment transaction (requires a funded signer).
- Mainnet approval (explicit go-ahead required, never assumed).
- Choosing the upgrade authority model.

## Honest limitations

- The adapter is new code bridging to audited-logic; the *bridge* (PDA
  checks, deserialization) has 6 unit tests but has never run on a real
  validator. `solana-test-validator` local testing is the next verification
  step before devnet.
- `solana-program` 4.1.0 is used with the Agave 4.3.0 toolchain (no 4.3.0
  exists on crates.io). The SBF ABI is stable across these; the smoke test
  and the identity build both succeeded.
- Timestamps come from the on-chain Clock — a validator-controlled value.
  Registration windows are coarse (365 days), so clock skew is not a
  practical concern here.
- This plan covers the identity program only. The token, staking, referral,
  transfer-hook, and anti-dump programs need their own adapters before any
  of them can deploy.
