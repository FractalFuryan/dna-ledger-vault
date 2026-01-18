# Claims Register

**Purpose:** Explicit categorization of all claims (grounded vs speculative)  
**Status:** Enforced via CI  
**Last Updated:** January 18, 2026

---

## Grounded (Mathematics)

**Status:** Classical, unchanged, non-owned

- ✅ We use the **classical Gaussian explicit formula** as a fixed mathematical substrate
- ✅ All number-theoretic identities are **standard results** from analytic number theory
- ✅ No new **theorems** or **proofs** are claimed
- ✅ No modifications to **classical zeta function theory**

**References:**
- Gaussian explicit formula: Standard textbooks (e.g., Davenport, Montgomery-Vaughan)
- Prime number theory: Classical analytic number theory
- Riemann zeta function: Standard complex analysis

---

## Interpretive / Constraint-Layer (Speculative, Optional)

**Status:** Optional framework, falsifiable at constraint level

- 🟡 We propose an **optional stability constraint**: Off-critical spectral mass is treated as instability under bandwidth refinement
- 🟡 This constraint is **test-function dependent** (Gaussian smoothing parameter σ)
- 🟡 This is **not** a theorem, **not** a proof, **not** physics
- 🟡 This is an **interpretive lens** that may be accepted, rejected, or modified

**Key property:** Conditional claim ("if one treats X as Y, then Z follows analytically")

**Falsifiability:** At the constraint level (not mathematical truth level)

---

## Engineering (GeoPhase / Crypto)

**Status:** Independent of interpretive layer, auditable

- ✅ Cryptographic mechanisms (e.g., **RFC6979 deterministic nonces**, commitments, attestations) are **independent** of the interpretive layer
- ✅ **ChaCha20-Poly1305 AEAD** provides authenticated encryption (standard primitive)
- ✅ **Reed-Solomon error correction** provides transport robustness (classical coding theory)
- ✅ **Merkle proofs** provide cryptographic audit trails (standard data structure)
- ✅ **Ethereum/Base L2** integration uses standard smart contracts (no novel cryptography)

**Key property:** Engineering claims are **verifiable**, **testable**, and **auditable**

**No dependency on:** Scalar Waze interpretation, FHCM framework, or speculative claims

---

## Privacy & Ethics (DNA Ledger Vault)

**Status:** Enforced via design, tested, auditable

- ✅ **Commitments only** on-chain (no media, no likeness, no user data)
- ✅ **No behavioral tracking** (privacy-safe metrics only)
- ✅ **User-controlled revocation** (on-chain capability)
- ✅ **Ethics anchor** immutable (SHA-256 hash of ethics invariants)
- ✅ **Fail-closed defaults** (STRICT_CHAIN, STRICT_REVOCATION)

**Key property:** Privacy guarantees are **structural**, not policy-based

---

## Layering Integrity (Critical Property)

**No layer depends on belief in the layer above it.**

```
Classical Math (grounded)
    ↓
Interpretive Constraints (optional)
    ↓
Engineering Systems (independent)
    ↓
Cryptographic Enforcement (auditable)
```

**Consequences:**
- You can **reject** the interpretive layer and still use the engineering
- You can **verify** the crypto without understanding the math
- You can **audit** the privacy guarantees without accepting speculative claims

---

## How to Add New Claims (Process)

1. **Identify category:** Grounded / Interpretive / Engineering
2. **Check independence:** Does this create a dependency on an upper layer?
3. **Document boundary:** Add to this register with clear status
4. **Update docs:** Ensure `SCALAR_WAZE_BOUNDARY.md` and `NON_CLAIMS.md` reflect the addition
5. **Run boundary gate:** `make boundary` must pass

---

## Enforcement

This register is enforced via:

1. `tools/check_boundaries.py` - Automated verification
2. `.github/workflows/boundary_gate.yml` - CI gate
3. Code review - Human verification
4. Documentation index - Cross-reference integrity

---

## References

- Mathematical claims: Standard analytic number theory textbooks
- Interpretive claims: `docs/SCALAR_WAZE_BOUNDARY.md`
- Engineering claims: DNA Ledger Vault technical documentation
- Privacy claims: `docs/REGULATOR-SUMMARY.md`, `docs/WHAT-THIS-IS-NOT.md`

---

**Status:** ✅ Claims categorized and enforced  
**Philosophy:** Grounded math. Optional interpretation. Independent engineering.
