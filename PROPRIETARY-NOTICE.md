# Proprietary Components Notice

**Effective Date**: 2026-01-17  
**Repository**: github.com/FractalFuryan/dna-ledger-vault

---

## Scope of This Notice

This repository intentionally separates **verifiable trust code** (open source) from **proprietary execution logic** (closed source).

The goal is to enable:
- ✅ Regulatory verification of ethics compliance
- ✅ Cryptographic auditability of commitments
- ✅ Third-party verification of privacy boundaries
- ❌ Without disclosing competitive trade secrets

---

## Open Source Components (MIT License)

The following components are open source under the MIT License:

### Trust Layer
- **Commitment formats** (`geophase_eth/eth/geocommit.py`, PREFIX_V1)
- **Ethics anchors** and invariant specifications
- **Smart contracts** (AnankeAttestationRegistry, AnankeRevocationRegistry)
- **Public API specifications** (request/response schemas only)
- **Zero-knowledge proof specifications** (statements, constraints, security bounds)
- **Test harnesses** proving determinism and fail-closed behavior
- **Documentation** explaining *what* is enforced and *how* to verify

**Purpose**: Enable independent verification of system safety and ethics compliance.

---

## Proprietary Components (All Rights Reserved)

The following components are **NOT open source** and are excluded from any public license grant:

### Living Cipher Engine
- **GeoPhase internal algorithms** (exact transforms, constants, schedules)
- **Dual-phase coupling logic** (Phase A / Phase B interaction mechanisms)
- **Cosine buffer implementation** (specification OK, code closed)
- **Teleport heuristics, thresholds, and schedules**
- **Parameter tuning, weights, and entropy routing**
- **State mixer implementation details** (enhanced_F_k exact math)
- **GPU / shader implementations** and optimizations
- **SIMD, batching, and performance optimizations**
- **Production FastAPI wiring** beyond public gate interfaces
- **Any nontrivial "how it works internally" implementation details**

**Purpose**: Protect competitive advantage, safety mechanisms, and sustainability.

---

## Legal Boundaries

### What You May Do
✅ Use open source components under MIT License  
✅ Verify commitment computations independently  
✅ Audit smart contracts and specifications  
✅ Implement alternative clients using public specifications  
✅ Build tools that interact with public API surface

### What You May NOT Do
❌ Reverse engineer proprietary components  
❌ Extract or derive proprietary algorithms from binaries  
❌ Create derivative works based on proprietary logic  
❌ Redistribute or sublicense proprietary components  
❌ Use proprietary components without explicit written permission

---

## Why This Separation Matters

### For Regulators
- Can verify ethics compliance without accessing trade secrets
- Can audit commitment formats and privacy guarantees
- Can review smart contracts and on-chain behavior
- Cannot access competitive implementation details

### For Users
- Can verify system enforces stated privacy boundaries
- Can audit that commitments reveal no sensitive data
- Can independently check revocation enforcement
- Do not need to trust implementation internals for safety verification

### For Competitors
- Can see *what* the system does (public specifications)
- Cannot see *how* it works efficiently (proprietary optimizations)
- Can build alternative implementations from specifications
- Cannot copy competitive advantages

### For Sustainability
- Protects business model and competitive position
- Enables open verification without giving away the store
- Supports long-term development and security maintenance
- Prevents commoditization while maintaining trust

---

## Information Asymmetry, Not Obfuscation

This approach follows industry best practices:

**What We PUBLISH**:
- Specifications and interfaces
- Invariants and constraints
- Proof that safety properties exist
- Cryptographic commitments and hashes
- Zero-knowledge proof statements (not optimized circuits)

**What We DO NOT PUBLISH**:
- Exact mathematical constants and coefficients
- Exact mixing and transformation functions
- Exact entropy routing and teleport schedules
- Performance optimizations and implementation tricks
- "Why this works well" tuning rationale

**Result**:
- ✅ Regulator confidence (can verify safety)
- ✅ User trust (can verify privacy)
- ✅ Open-source legitimacy (trust layer is open)
- ✅ Trade secret protection (competitive advantage preserved)
- ✅ Zero information leakage about proprietary logic

---

## Enforcement

Reverse engineering, extraction, or derivative use of proprietary components is:
1. Prohibited by this notice
2. Prohibited by applicable trade secret law
3. Grounds for legal action
4. Subject to injunctive relief and damages

If you are unsure whether a component is open or proprietary, **contact us before using it**.

---

## Implementation Guidelines

### Naming Conventions (Enforced)
- **Anything called**: cipher, engine, core, kernel, runtime → **PROPRIETARY**
- **Anything called**: spec, registry, bridge, attestation, gate → **OPEN**

### Directory Structure
```
/contracts          → MIT (trust layer)
/geophase_eth       → MIT (trust layer)
/docs               → MIT (specifications only)
/living-cipher      → PROPRIETARY (not in public repo)
/ananke-core        → PROPRIETARY (not in public repo)
```

### CI Enforcement
- Build fails if proprietary directories appear in public artifacts
- Build fails if proprietary symbols leak into open modules
- Automated license header checks

---

## Standard Disclaimer (Copy/Paste for Docs)

Add this to any document describing internal algorithms:

```md
Note on Implementation:
This document describes *verifiable properties* and *constraints* of the
system. It does not disclose internal algorithms, constants, schedules,
or optimization strategies used in production.

Multiple distinct implementations may satisfy this specification.
Proprietary implementation details are protected as trade secrets.
```

---

## Zero-Knowledge Circuits (Special Case)

### Public
- ZK statement (what is being proven)
- Constraint categories (types of checks)
- Security bounds (soundness, zero-knowledge guarantees)
- Field-valid operations (what arithmetic is safe)

### Proprietary
- Gate layouts and circuit structure
- Lookup table contents and encodings
- Optimization tricks (constraint reduction, etc.)
- Exact field element decompositions
- Witness generation optimizations

**Specification includes**: "This specification intentionally omits circuit-level optimizations, gate layouts, and lookup table encodings, which are treated as proprietary implementation details."

---

## Contact for Licensing

For inquiries about licensing proprietary components:
- **Email**: (to be provided)
- **Repository**: https://github.com/FractalFuryan/dna-ledger-vault
- **Issues**: Use public issue tracker for trust layer questions only

**Do not request proprietary source code via public channels.**

---

## Version History

- **v1.0** (2026-01-17): Initial proprietary notice
- **v1.1** (TBD): Updates based on legal review

---

## Acknowledgments

This approach follows established patterns from:
- **Cryptographic libraries**: Specifications public, optimizations private
- **Database systems**: SQL standard public, query optimizer private
- **Compilers**: Language spec public, optimization passes private
- **Security tools**: Protocols public, detection heuristics private

**Philosophy**: *Open rules. Closed engines. Auditable guarantees.*
