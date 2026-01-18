# Non-Claims (Hard Boundary)

**Status:** Enforced via CI  
**Last Updated:** January 18, 2026

---

## What This Work Does NOT Claim

This work does **not** claim:

- ❌ A proof or disproof of the **Riemann Hypothesis**
- ❌ A modification of the **explicit formula**
- ❌ A new **zeta function identity**
- ❌ A physical realization of the **zeta function**
- ❌ Empirical predictions about **matter, cognition, or consciousness**
- ❌ A new **number-theoretic theorem**
- ❌ Ownership of **classical mathematical results**

---

## Scope Limitation

All speculative statements are confined to **interpretive constraint analysis** and are **labeled as such**.

No mathematical results are modified, extended, or claimed as original unless explicitly documented with full derivation and attribution.

---

## Category Boundaries

| Category | Status | Claims Allowed |
|----------|--------|----------------|
| Classical number theory | **Unchanged** | None (use standard references) |
| Interpretive constraints | **Optional** | Conditional, falsifiable statements only |
| Engineering systems | **Independent** | Cryptographic, algorithmic properties |
| Empirical predictions | **None** | Not applicable to this work |

---

## How to Identify Speculation

Any statement prefixed with:
- "If one treats..."
- "Under the constraint that..."
- "As an interpretive lens..."
- "Speculatively..."

...is explicitly marked as **non-mathematical**, **optional**, and **falsifiable** at the constraint level.

---

## Enforcement

This boundary is enforced via:

1. `tools/check_boundaries.py` - Automated snippet verification
2. `.github/workflows/boundary_gate.yml` - CI gate
3. Code review guidelines - Human verification
4. Documentation index - Clear labeling

Any PR that introduces claims outside this scope will fail CI.

---

## References

- Mathematical substrate: Classical analytic number theory (standard textbooks)
- Interpretive layer: `docs/SCALAR_WAZE_BOUNDARY.md`
- Engineering layer: DNA Ledger Vault documentation

---

**Status:** ✅ Hard boundary enforced  
**Philosophy:** Math untouched. Interpretation optional. Claims falsifiable.
