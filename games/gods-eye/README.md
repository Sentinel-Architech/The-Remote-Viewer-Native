# God's Eye

**PART 2 of one journey.** God's Eye is the decentralized globe the player
reaches after **Neural Mesh (part 1)**: as viruses and ailments are cured
and every neural zone is healed, the **Great Ascent** transitions the
player from the healed mind into this world. Part 2 is **locked** until
part 1 is complete. The two games are one story, not two apps.

One of only **two** simulation games in The Remote Viewer Network. The
other is **Neural Mesh**. Both are educational for the Sentinel.

## Premise

You are a homeland-security cyber analyst with God's Eye — a live view
of a network under attack. Threats appear across the grid. You triage,
investigate, and contain them before they escalate. The calmer and
faster you are, the higher your grade.

This is not fantasy hacking. Every threat in the game maps to a real
threat-awareness lesson: phishing, worms, supply-chain compromise,
ransomware, insider abuse, DDoS, social engineering. The game teaches
the player to think like a defender — and every mission teaches the
Sentinel how its human learns.

## Core loop

1. **Briefing** — the mission scenario, the stakes, the threat roster.
2. **Mission** — threats spawn on the network grid. Each has a response
   window (shorter at higher difficulty). Contain threats before they
   escalate; escalating threats deal more damage the longer they burn.
3. **Debrief** — grade (S/A/B/C/D/F), integrity report, and the lesson
   each threat was teaching. The Sentinel records what the player
   struggled with to tutor them later.

## Educational goals (threat awareness)

| Threat | Lesson |
|---|---|
| Phishing | Verify the sender. Never click blind links. |
| Worm | Patch promptly. Segment your networks. |
| Supply chain | Trust the supply chain only after verification. |
| Ransomware | Keep offline backups. Never pay the ransom. |
| Insider | Least privilege. Audit everything. |
| DDoS | Rate-limit at the edge. Filter upstream. |
| Social engineering | Verify identity out-of-band before sharing secrets. |

## Controls (platform layer)

- Tap/click a threat to inspect it (shows kind, behavior, time left).
- Contain action per threat type (quarantine, block, revoke, filter).
- Misclicking (containing a non-threat) costs points — precision matters.
- Difficulty: Cadet → Analyst → Sentinel.

## Win / lose states

There is no binary win/lose. The mission always runs its clock; the
debrief grades you:

- **S** — flawless: every threat contained, network pristine.
- **A/B/C/D** — graded on containment rate and network integrity.
- **F** — the network was lost (integrity hit zero), or containment
  collapsed.

Losing teaches: the debrief shows exactly which lesson each missed
threat was carrying.

## Presentation

- **High resolution, immersive.** The network grid is rendered as a
  living system — nodes pulse, threats smolder green-to-red as they
  escalate, containment blooms outward.
- **Vortex transitions** in and out of the game and between events
  (see `src/vortex.rs`): a spiral tunnel in the Sentinel's green,
  entered through the Sentinel's eye. Skippable / reduced-motion
  safe for accessibility.
- **Adaptive:** the Sentinel goes above and beyond on capable devices
  and scales the visuals down gracefully on weaker ones.

## Code layout

- `src/state.rs` — game state machine (menu → briefing → mission → debrief)
- `src/threats.rs` — threat entities, kinds, behaviors, lifecycle
- `src/scoring.rs` — points, integrity, grades
- `src/vortex.rs` — vortex transition as data for the renderer
- `src/journey.rs` — part-2 side of the single-journey contract

Pure logic, std-only, zero dependencies. Rendering lives in the
platform layer. See also: the game's integration contract with the
Sentinel tutoring system (TBD).

## The single journey

Neural Mesh (part 1) and God's Eye (part 2) are **one journey**, joined
by the contract in `games/shared/` (`trv-game-journey`):

- **Trigger:** part 2 unlocks only when every neural zone is healed in
  part 1. The platform layer calls `trv_game_journey::try_unlock` on the
  journey save; `Err(PartOneIncomplete)` means the globe stays locked —
  show the player the way back to the Mesh.
- **Arrival:** the player enters through the **Great Ascent** (3.0s,
  30 rings) into the mission briefing, greeted by the journey briefing
  line (`journey::journey_briefing`).
- **Carried state:** the part-1 healing score arrives as **reputation**
  (starting bonus points via `Score::grant_reputation`); accuracy maps
  to the suggested starting **difficulty** (`journey::difficulty_for`).
- **Save format:** part 1 writes a fixed 13-byte versioned save
  (`TRVJ` magic); part 2 decodes it fail-closed before unlocking.
- Both crates stay standalone; the shared contract is a path-only,
  std-only dependency — zero external dependencies anywhere.
