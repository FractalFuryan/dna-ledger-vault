# v0.2 Design Notes (Documentation Only)

**Status**: Planning phase, no implementation  
**Purpose**: Document future enhancements without commitment  
**Date**: 2026-01-17

---

## Core Principle (Unchanged)

⭕️🛑 **Privacy-safe commitments only**

v0.2 maintains the same privacy boundary:
- Commitments on-chain
- No media, no likeness, no user data
- No new trust assumptions

---

## Goals

1. **Preserve v0.1 privacy model** (commitments only)
2. **Keep contracts minimal and auditable**
3. **Avoid tradable "content ownership" semantics**
4. **Improve revocation authorization** (prevent spam/griefing)
5. **Optional NFT layer** (regeneration rights, not media)

---

## Candidate Extensions

### 1. Signature-Gated Revocation

**Problem**: v0.1 allows anyone to revoke any commitment (open revocation)  
**Risk**: Spam attacks, griefing, denial of service

**Proposal**:
- Add `authorizedRevoker` mapping to revocation registry
- Require signature from authorized party to revoke
- User can designate multiple authorized revokers (self + trusted delegates)

**Interface**:
```solidity
function authorize(bytes32 commitment, address revoker) external;
function revoke(bytes32 commitment, bytes calldata signature) external;
```

**Benefits**:
- Prevents unauthorized revocations
- Maintains user control (can authorize self or delegates)
- No gas cost for authorization (off-chain signature)

**Trade-offs**:
- Slightly more complex UX (signature required)
- Requires key management for revocation authority

---

### 2. Seed-Rights NFT (Regeneration Rights Only)

**Problem**: Regeneration capability currently tied to commitment only  
**Opportunity**: Optional transferable regeneration rights

**Proposal**:
- ERC-721 token representing right to regenerate from a commitment
- Token ID → `seedCommit` (hash), NOT seed plaintext
- Revocation still keyed by `geoCommit` or `tokenIdCommit`
- **No media URIs, no metadata URIs, no content storage**

**Interface**:
```solidity
contract AnankeSeedRightsNFT is ERC721 {
    mapping(uint256 => bytes32) public seedCommitOf;
    mapping(uint256 => bytes32) public policyIdOf;
    
    function mint(address to, bytes32 seedCommit, bytes32 policyId) external returns (uint256);
}
```

**Benefits**:
- Transferable regeneration capability
- Compatible with existing NFT infrastructure
- Maintains commitment-only privacy model

**Trade-offs**:
- Introduces token transfer market (may not align with ethics)
- Requires careful framing to avoid "content ownership" misinterpretation

**Recommendation**: Document but **do not implement** until ethics review

---

### 3. EAS Attestations Mirror (Optional)

**Problem**: Ethereum Attestation Service (EAS) ecosystem tooling not directly compatible  
**Opportunity**: Mirror attestations to EAS for broader visibility

**Proposal**:
- Optional EAS attestation schema mirroring `AnankeAttestationRegistry` fields
- Same commitment fields, same privacy model
- No new data, just alternate format

**Benefits**:
- Compatibility with EAS-based dashboards and analytics
- Broader ecosystem integration
- No trust assumptions added

**Trade-offs**:
- Duplicate storage (higher gas costs)
- Maintenance of two registries

**Recommendation**: Wait for ecosystem demand before implementing

---

### 4. Read-Only Event Indexer

**Problem**: Querying historical attestations/revocations requires full node  
**Opportunity**: Lightweight indexer for audit logs

**Proposal**:
- Off-chain indexer for `Attested` and `Revoked` events
- Exports CSV or JSON for audit purposes
- No new trust in generation pipeline

**Interface** (example):
```bash
python -m geophase_eth.indexer export --from-block 0 --to-block latest
```

**Output**:
```csv
block,tx_hash,event,geoCommit,ethicsAnchor,policyId,version,timestamp
12345,0xabc...,Attested,0x111...,0x65b...,0x222...,1,1705449600
12346,0xdef...,Revoked,0x111...,,,,,1705449700
```

**Benefits**:
- Easy audit trail export
- No additional on-chain trust
- Simple tooling for compliance reporting

**Recommendation**: Implement as optional CLI tool

---

### 5. Batch Attestation Support

**Problem**: Attesting many commitments requires many transactions (high gas)  
**Opportunity**: Batch attestations in single transaction

**Proposal**:
```solidity
function attestBatch(
    bytes32[] calldata geoCommits,
    bytes32 ethicsAnchor,
    bytes32 policyId,
    uint32 version
) external;
```

**Benefits**:
- Lower total gas cost
- Faster deployment for bulk attestations

**Trade-offs**:
- More complex contract logic
- Potential gas limit issues for very large batches

**Recommendation**: Add if real-world usage shows need

---

## Non-Goals (Explicit Exclusions)

### ❌ On-Chain Media Storage
**Rationale**: Violates privacy-only boundary, creates storage/bandwidth burden

### ❌ Likeness/Biometric Representation On-Chain
**Rationale**: Violates core ethics, creates re-identification risk

### ❌ Behavioral Analytics or Engagement Tracking
**Rationale**: Violates privacy posture, creates surveillance infrastructure

### ❌ Content Recommendation Algorithms
**Rationale**: Out of scope for provenance layer

### ❌ Marketplace or Royalty Mechanisms
**Rationale**: Avoids financialization of genomic-derived outputs

### ❌ Cross-Chain Bridges (v0.2)
**Rationale**: Complexity without clear benefit, defer to future

---

## Architecture Considerations

### Multi-Network Deployment

**Consideration**: Deploy to multiple L2s (Base, Arbitrum, Optimism, Polygon)?

**Analysis**:
- **Pros**: User choice, redundancy, ecosystem reach
- **Cons**: Fragmented state, higher maintenance, no clear demand signal
- **Decision**: Stay Base-only for v0.2, evaluate demand

### ZK Proof Integration (Halo2 Option A)

**Consideration**: Verify teleport chains on-chain?

**Analysis**:
- **Pros**: Fully trustless GeoPhase verification
- **Cons**: High gas costs, complex circuit maintenance
- **Decision**: Spec complete, implementation deferred to v0.3+

### Time-Locked Attestations

**Consideration**: Delayed reveal for commitments?

**Analysis**:
- **Use case**: Attest now, reveal parameters later
- **Mechanism**: Commit to `geoCommit`, reveal `seed_commit || phaseA || phaseB` later
- **Decision**: Interesting but unclear user demand, document for future

---

## Testing & Validation Plan (v0.2)

If v0.2 proceeds, add:

1. **Signature verification tests** (revocation auth)
2. **NFT minting + transfer tests** (if included)
3. **Batch attestation gas benchmarks**
4. **Indexer correctness tests** (event parsing)
5. **Cross-client commitment determinism** (Python + Solidity)

---

## Migration Path (v0.1 → v0.2)

### Contract Deployment
- Deploy new contracts alongside v0.1 (no replacement)
- v0.1 contracts remain live indefinitely
- Users opt-in to v0.2 features

### Client Updates
- Server adds v0.2 endpoint routes
- Legacy v0.1 gate remains available
- Dual compatibility period (6 months minimum)

### Deprecation Policy
- No forced migration
- v0.1 supported indefinitely for existing commitments
- New commitments encouraged to use v0.2 (if benefits clear)

---

## Open Questions

1. **NFT ethics**: Does transferable regeneration align with genomic data ethics?
2. **Revocation authority**: Should users be able to delegate to multiple parties?
3. **Gas optimization**: Is batch attestation worth complexity?
4. **Cross-chain**: Any real demand for multi-L2 deployment?
5. **Indexer trust**: Should indexer be self-hosted or offered as service?

---

## Decision Framework

Proceed with v0.2 extension if:

1. ✅ Maintains v0.1 privacy boundary (commitments only)
2. ✅ Adds clear user value (not speculative)
3. ✅ Keeps contracts auditable (no complexity explosion)
4. ✅ Passes ethics review (especially NFT layer)
5. ✅ Has real demand signal (not just "could be useful")

---

## Timeline (Tentative)

- **Q1 2026**: v0.1.1 hardening (done)
- **Q2 2026**: Signature-gated revocation design + audit
- **Q3 2026**: Indexer tool implementation
- **Q4 2026**: NFT ethics review + potential prototype
- **Q1 2027**: v0.2 deployment decision based on learnings

---

## References

- [REGULATOR-SUMMARY.md](REGULATOR-SUMMARY.md) — Compliance documentation
- [THREAT-MODEL-ETH.md](THREAT-MODEL-ETH.md) — Security threat analysis
- [GEO-COMMIT-SPEC.md](GEO-COMMIT-SPEC.md) — Commitment format specification
- [WHAT-THIS-IS-NOT.md](WHAT-THIS-IS-NOT.md) — Boundary clarifications
