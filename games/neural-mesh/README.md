# Neural Mesh (code name: `neural-link`)

> **EDUCATIONAL ENTERTAINMENT — NOT MEDICAL ADVICE.** Neural Mesh is a game.
> It does not diagnose, treat, or prevent any condition. Nothing in it should
> be used to assess or address any health concern. For anything health-related,
> consult a qualified medical professional.

**PART 1 of one journey.** Neural Mesh starts in the brain; as viruses and
ailments are cured — every neural zone healed — the **Great Ascent**
transitions the player into **God's Eye (part 2)**, the decentralized globe.
God's Eye stays locked until this dive is complete. The two games are one
story, not two apps. See [The single journey](#the-single-journey) below.

One of the only **TWO** simulation games in the TRV DApp. A matrix-themed
journey through the brain: the player dives with the Sentinel into a stylized
neural landscape, explores brain zones, resolves anomalies through educational
challenges, and ascends. HIGH RESOLUTION, immersive, relevant.

## Premise

You are a Remote Viewer. The Sentinel opens a vortex — a spiraling tunnel of
light — and dives you into a living map of the human brain rendered as an
endless matrix grid. Friendly neurons pulse along the pathways. But anomalies
drift through the zones: Fog Banks, Static Storms, Fading Echoes. Each one
carries a lesson about brain health. Resolve them, restore Neural Integrity,
master every zone, and ascend.

The game is also **educational for the Sentinel**: anonymized, on-device
play patterns (which topics players engage with, never personal data) help
the Sentinel learn what brain-health awareness topics matter most to its
viewer.

## Core loop

1. **Menu** — title screen + the medical disclaimer (must be acknowledged).
2. **Dive** — full vortex transition into the first zone (Cortex Fields).
3. **Explore** — move through the zone, link friendly neurons (+10 synapse points).
4. **Encounter** — approach an anomaly → educational challenge begins.
5. **Challenge** — answer the awareness question. Correct: difficulty-scaled
   points + integrity restored. Wrong: small consolation points, tiny
   integrity dip — a teaching moment, never a punishment.
6. **Resolution** — rewards applied, event vortex swirl.
7. **Master the zone** — clear its anomalies → zone mastered.
8. **Shift** — lateral vortex into the next zone.
9. **Ascent** — full vortex out, session summary (score, accuracy, integrity).

## Neural zones (dive order)

| Zone | Flavor |
|---|---|
| Cortex Fields | Where thoughts take shape. Logic and pattern challenges. |
| Hippocampus Vaults | Memory vaults. Recall and association. |
| Limbic Weather | Emotional weather. Stress-awareness scenarios. |
| Brainstem Core | The oldest rhythm. Breathing and focus. |
| Cerebellum Lattice | Balance is practice. Coordination trials. |

## Anomalies & educational goals

All topics are **general awareness, medically relevant to 2026 as creative
direction — never medical claims**:

- **Fog Bank** — sleep supports memory consolidation.
- **Static Storm** — chronic stress affects focus; coping strategies help.
- **Dry Static** — hydration supports everyday alertness.
- **Fading Echo** — repetition and rest strengthen learning.
- **Crimson Surge** — know stroke warning signs (FAST: Face, Arms, Speech,
  Time). In a real emergency, call emergency services immediately.
- **Fracture Line** — head injuries deserve rest and professional evaluation.

## Controls (platform layer)

- **Move/look**: touch drag or device tilt (platform implements).
- **Link neuron**: tap.
- **Answer challenge**: multiple-choice cards.
- **Ascend**: hold the ascent glyph.
- All input is abstracted — this crate models logic only.

## Progression

- **Synapse points**: score. Correct answers scale with anomaly difficulty
  (1–3). Full-dive bonus (+250) for mastering all five zones.
- **Neural Integrity**: 0–100. Rises on resolves, dips slightly on misses,
  floored at 0 — never punitive.
- **Accuracy**: resolved / attempted.

## The vortex transition

The signature transition, documented as a timing contract in
`src/vortex.rs`:

- **DiveIn** (2.4s, 24 rings, inward) — menu → first zone.
- **AscentOut** (2.0s, 20 rings, outward) — zone → summary.
- **ZoneShift** (1.2s, 12 rings, lateral) — between zones.
- **EventSwirl** (0.6s, 6 rings, inward) — anomaly resolved, zone mastered.

Renderers must honor these durations; game logic waits on them. A
reduced-motion crossfade alternative keeps identical timing
(accessibility).

## Crate layout

```text
games/neural-mesh/
├── Cargo.toml          # standalone crate (not in parent workspace)
├── README.md           # this design doc
├── src/
│   ├── lib.rs          # modules + MEDICAL_DISCLAIMER
│   ├── state.rs        # Game state machine (menu→dive→zones→ascent)
│   ├── zones.rs        # Zone & entity types, anomaly topics
│   ├── progression.rs  # scoring, integrity, accuracy
│   ├── journey.rs      # part-1 side of the single-journey contract
│   └── vortex.rs       # transition concept + timing contract
└── tests/
    └── logic_tests.rs  # scripted full-dive integration tests
```

Std-only, zero dependencies. Rendering, audio, and input live in the
platform layer (Android/UI crates) and are out of scope here.

## The single journey

Neural Mesh and God's Eye are **one journey in two parts**, joined by the
contract in `games/shared/` (`trv-game-journey`):

- **Trigger:** part 2 unlocks only when every neural zone is mastered.
  Anything less and God's Eye stays locked.
- **Transition:** the **Great Ascent** vortex (3.0s, 30 rings) carries the
  player from the healed mind outward into the decentralized globe —
  see `VortexKind::GreatAscent`.
- **Carried state:** the healing score becomes globe **reputation**
  (starting bonus points); integrity and accuracy become **influence**;
  accuracy suggests the starting **difficulty** (≥90 → Sentinel,
  ≥70 → Analyst, else Cadet).
- **Save format:** a fixed 13-byte versioned save (`TRVJ` magic) that
  part 1 writes and part 2 reads; decoding fails closed on corruption.
- Both crates stay standalone; the shared contract is a path-only,
  std-only dependency — zero external dependencies anywhere.

## Status

Logic scaffold complete and tested. Not yet wired into the app, not
rendered, not deployed. The handwritten game logic has not been
externally audited — consistent with the rest of the native stack.
