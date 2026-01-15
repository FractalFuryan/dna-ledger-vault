# Dual Geo-Phase (Audit-only Cosine Buffer)

⭕️🛑 **Public-safe architecture note**

## Summary

Dual Geo-Phase is a two-projection system:
- **GeoPhase A:** seed → render-driving parameter vector
- **GeoPhase B:** seed → audit-only vector (orthogonal mapping)

A cosine similarity check is used **only for audit reporting**, never for runtime gating.

## Why two phases

This provides a measurable "non-collapse tendency" in parameter space without introducing:
- re-roll loops
- hidden optimization
- implicit scoring systems
- content-based filtering

## Cosine buffer rule

- compute cosine similarity between vectors (or their normalized forms)
- report statistics (mean/variance/quantiles) in attestations
- **never** use the cosine result to trigger regeneration, rejection, or resampling

## Prohibited implementations

- No image embeddings
- No anatomy detectors
- No iterative loops to "increase distance"
- No personalization or memory accumulation

## Intended audit outputs

Example metrics:
- distribution of cos(A, B) over N seeds
- stability across commit versions
- detection of accidental collapse (e.g., if mapping becomes degenerate)

This is a **measurement layer**, not an enforcement layer.

---

## Why No Runtime Cosine Gating

The cosine buffer is **audit-only** by design. Using it for runtime gating would introduce severe risks:

### 1. Stealth Optimization Loops
Runtime gating creates implicit feedback:
- reject output → resample → measure again → accept/reject
- system learns "acceptable" parameter regions
- converges toward hidden attractor states
- violates "no learning" invariant

### 2. Implicit Scoring System
Any runtime threshold (`cos(A,B) > τ → reject`) becomes a scoring function:
- outputs below threshold are "bad"
- outputs above threshold are "good"
- creates implicit quality hierarchy
- enables gradual drift toward higher scores

### 3. Hidden Filter Loop
Resampling based on cosine similarity:
- filters parameter space without explicit policy
- creates "successful output" distribution
- learns user preferences through acceptance rates
- accumulates bias over time

### 4. Measurement Distortion
Using measurements for enforcement corrupts the measurement:
- Goodhart's Law: "When a measure becomes a target, it ceases to be a good measure"
- cosine buffer designed to detect collapse, not prevent it
- runtime gating makes it untrustworthy for detection

### 5. Architecture Integrity
Enforcement belongs in **policy + structure layers**:
- hard invariants (no memory, no personalization loops)
- deterministic generation (seed → output, no retries)
- audit measurements stay independent of runtime decisions

**Conclusion:** Runtime cosine gating would violate the ethics anchor by introducing hidden optimization, implicit scoring, and measurement corruption. The audit-only posture preserves system integrity.
