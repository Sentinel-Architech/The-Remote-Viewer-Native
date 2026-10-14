# trv-game-journey

The **single-journey contract** between the two TRV simulation games:

- **Neural Mesh (part 1)** — starts in the brain. As viruses and ailments
  are cured and every neural zone is healed, the journey continues.
- **God's Eye (part 2)** — the decentralized globe. Locked until part 1
  is complete.

## The contract

1. **Trigger:** `try_unlock(&summary)` succeeds **only** when every
   neural zone is mastered (`zones_mastered == zones_total`). Anything
   less → `JourneyError::PartOneIncomplete`, and part 2 stays locked.
2. **Transition:** the **Great Ascent** vortex — 3.0s, 30 rings, outward —
   carries the player from the healed mind into the globe. It is the
   longest vortex in either game, because the player is leaving one world
   for another.
3. **Carried-over state** (healing → globe):
   - `synapse_score` → **reputation** (starting bonus points in part 2)
   - `(integrity + accuracy) / 2` → **influence** (0..=100)
   - `accuracy` → suggested **difficulty**: ≥90 Sentinel, ≥70 Analyst,
     else Cadet
4. **Save format** (v1, fixed 13 bytes): `TRVJ` magic + version +
   zones mastered/total + synapse score (u32 LE) + integrity + accuracy.
   Part 1 writes it; part 2 reads it. Decoding fails closed on bad
   magic, version, length, or out-of-range fields.

## Neutrality

This crate knows nothing about either game's internals. Each game adapts
via a small `journey` module:

- `neural-mesh/src/journey.rs` — `Progress` → `NeuralSummary`
- `gods-eye/src/journey.rs` — `AnalystProfile` → difficulty + reputation

Both games depend on this crate by path only. Std-only, zero
dependencies — consistent with the rest of the native stack.

## Layout

```text
games/shared/
├── Cargo.toml              # standalone crate (not in parent workspace)
├── README.md               # this doc
├── src/
│   ├── lib.rs              # crate docs + re-exports
│   └── transition.rs       # trigger, carried state, save format
└── tests/
    └── transition_tests.rs # end-to-end journey contract tests
```
