# Engineering TODO — 2026-01-15

⭕️🛑 **Public-safe implementation task list**

## Docs added (done)
- THREAD-2026-01-15.md
- ETHICS-PROBABILISTIC-DISTANCE.md
- GEO-PHASE.md
- STATE-MIXER-FK.md
- ZK-TELEPORT-OPTION-A.md

## TODO (next commits)

### A) Glossary entry
- Add to docs glossary:
  - "Procedural personalization" vs "Likeness personalization"
- Ensure referenced by SECURITY.md and README.md if applicable

### B) No runtime cosine gating paragraph
- In GEO-PHASE.md, add an explicit rationale section:
  - prevents stealth optimization loops
  - prevents implicit scoring / resampling
  - ensures audit-only posture

### C) Halo2 Option A work plan
- Create a checklist for circuit build:
  - limb decomposition + range constraints
  - XOR lookup table integration
  - fixed-point scaling lookup + conventions
  - selector-bit branch correctness constraints
  - EC scalar multiplication constraint choice (native gadget)
  - final equality constraints

### D) CI docs gate (optional)
- Add a CI step to assert required docs exist
- Ensure docs are linked from README or SECURITY

### E) Evidence bundle command (optional)
- Add `cli export-evidence`:
  - bundle ledger + tip hash + schema version + doc refs
