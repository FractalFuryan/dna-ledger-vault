# What This Is NOT

⭕️🛑 **Clarity on boundaries for external observers**

---

## This System Does NOT

### ❌ Identity Personalization
- Does not reconstruct user identity
- Does not infer demographic attributes
- Does not build user profiles
- Does not predict user characteristics
- Parameters control **aesthetic preferences**, not identity features

### ❌ Likeness Reconstruction
- Does not generate images "of" users
- Does not create facial reconstructions
- Does not produce biometric representations
- Does not model individual appearance
- "Make it like me" = **procedural preset selection**, never likeness

### ❌ Biometric Hashing or Storage
- Does not store biometric data (facial, genomic, or otherwise)
- Does not create reversible biometric identifiers
- Does not enable biometric matching or re-identification
- Commitments are **cryptographically hiding**

### ❌ Media Storage
- Does not store generated outputs on-chain or in decentralized storage
- Does not create content URIs or IPFS links
- Does not persist media artifacts
- Ethereum layer stores **commitments only**

### ❌ Digital Rights Management (DRM)
- Does not enforce content access controls
- Does not implement copy protection
- Does not track content distribution
- Revocation blocks **regeneration**, not existing outputs

### ❌ Surveillance or Behavior Tracking
- Does not log user activity
- Does not track engagement patterns
- Does not build behavioral profiles
- Does not enable user monitoring
- Metrics are **system health only**, no user identifiers

### ❌ Engagement Optimization
- Does not A/B test content
- Does not optimize for retention or addiction
- Does not implement recommendation algorithms based on behavior
- Does not create filter bubbles or echo chambers

### ❌ Tradable Content Ownership
- Does not create NFTs representing media ownership
- Does not enable content resale or royalty streams
- Commitments represent **regeneration rights**, not content copyright
- No marketplace or transfer mechanisms (v0.1)

### ❌ Centralized Control
- Does not enable remote killswitch on existing outputs
- Does not implement backdoor access
- Does not store decryption keys for user data
- Revocation is **user-initiated or policy-driven**, not surveillance-driven

---

## What This System DOES

### ✅ Privacy-Safe Provenance
- Stores cryptographic commitments to GeoPhase parameters
- Enables verification without revealing data
- Provides audit trail for regeneration requests

### ✅ Revocation Enforcement
- Allows users to revoke regeneration capability
- Enforces revocation before processing requests
- Supports "right to be forgotten" for regeneration rights

### ✅ Ethics Compliance
- Anchors to immutable ethics document
- Prevents procedural drift via versioned commitments
- Enables regulator verification of ethics posture

### ✅ Decentralized Verification
- Anyone can verify attestation status
- No trusted third party required for verification
- Immutable audit trail on public blockchain

---

## Common Misconceptions Addressed

### "This is a biometric database"
**False**. This system stores **commitments** (cryptographic hashes) to procedural parameters, not biometric data. Commitments reveal nothing about underlying data and cannot be used for identification or matching.

### "This creates deepfakes of users"
**False**. GeoPhase generates outputs from genomic data + procedural parameters, not from user images or likeness. "Make it like me" refers to **preset selection** (aesthetic preferences), never to facial reconstruction or identity modeling.

### "This enables tracking users across platforms"
**False**. Commitments are **unlinkable** without knowledge of underlying seed. Each commitment is a fresh cryptographic hash. No cross-platform identifiers are created or stored.

### "This violates GDPR right to erasure"
**False**. Revocation mechanism provides functional deletion of **regeneration capability**. Existing outputs remain (as they are not stored on-chain), but future regeneration is permanently blocked.

### "This is surveillance infrastructure"
**False**. System stores **commitments only**, with no user identifiers, behavioral data, or tracking mechanisms. Metrics are system health only (RPC latency, error rates), with no user-identifying information.

---

## Why These Boundaries Matter

1. **Ethical AI**: Clear distinction between **procedural generation** and **identity reconstruction**
2. **Privacy**: Commitment-only storage prevents data reconstruction and re-identification
3. **Consent**: Users control regeneration capability, not content itself
4. **Trust**: Transparent boundaries enable informed consent and regulator confidence
5. **Safety**: Preventing misuse scenarios by design, not policy

---

## References

- [SECURITY.md](../SECURITY.md) — Overall security documentation
- [ETHICS-PROBABILISTIC-DISTANCE.md](ETHICS-PROBABILISTIC-DISTANCE.md) — Ethics doctrine
- [REGULATOR-SUMMARY.md](REGULATOR-SUMMARY.md) — Compliance summary
- [GEO-COMMIT-SPEC.md](GEO-COMMIT-SPEC.md) — Technical commitment specification
