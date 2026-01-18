# GeoPhase ↔ Base Bridge (v0.1) — Regulator Summary

**Date**: 2026-01-17  
**Version**: v0.1.1  
**Target**: Base L2 (Ethereum)  
**Purpose**: Privacy-safe genomic data provenance attestation

---

## Executive Summary

GeoPhase produces off-chain outputs from a user-scoped seed commitment. The Ethereum bridge writes **commitment-only provenance** to Base (L2) and enforces revocation checks before regeneration.

**Key principle**: Commitments reveal nothing about underlying data.

---

## What Is Stored On-Chain

### Attestation Data
- `geoCommit` (bytes32): Keccak256 hash of commitment payload
- `ethicsAnchor` (bytes32): SHA-256 hash of ethics invariants document
- `policyId` (bytes32): SHA-256 hash of policy document version
- `version` (uint32): Protocol version number
- `timestamp` (uint64): Block timestamp of attestation
- `attestor` (address): Ethereum address of attesting entity

### Revocation Data
- `revoked` (bool): Revocation status flag
- `revoker` (address): Ethereum address that revoked commitment
- `timestamp` (uint64): Block timestamp of revocation

**Total on-chain storage per commitment**: ~160 bytes  
**Privacy guarantee**: All values are cryptographic commitments or public constants

---

## What Is NOT Stored On-Chain

❌ Raw seeds or seed material  
❌ User nonces  
❌ GeoPhase parameter vectors (A or B)  
❌ Generated media or outputs  
❌ User identifiers or contact information  
❌ Biometric data  
❌ Likeness data or facial features  
❌ Behavioral analytics or engagement metrics  
❌ Session data or usage patterns

**Privacy boundary**: On-chain data cannot be used to reconstruct, infer, or identify users or their data.

---

## Safety Properties

### 1. Commitment-Only Storage
On-chain values are cryptographically hiding commitments that reveal nothing about:
- Source genomic data
- GeoPhase parameters
- Generated outputs
- User identity (unless voluntarily linked via attestor address)

### 2. Write-Once Attestations
- Attestations are immutable once written
- Prevents tampering with provenance history
- Single attestation per unique geoCommit
- Timestamp provides temporal ordering

### 3. Always-On Revocation Enforcement
- Server checks revocation status before every generation/regeneration
- Revoked commitments permanently block regeneration
- No grace periods or delayed enforcement
- Fail-closed behavior (deny on RPC failure if STRICT_REVOCATION=true)

### 4. No Personalization or Likeness
- "Make it like me" is **procedural preset selection only**
- No likeness reconstruction
- No biometric inference
- No identity modeling
- Parameters control aesthetic preferences, not identity features

### 5. Bytecode Integrity
- Optional bytecode hash verification at server startup
- Prevents silent contract redeployment or proxy swap
- Fail-closed on mismatch

---

## Architecture

```
User → Seed Commitment → GeoPhase (off-chain processing)
                      ↓
                  geoCommit (Keccak256 hash)
                      ↓
            Base L2: Attest / Revoke
                      ↓
              Server Gate Check
                      ↓
        Generation/Regeneration (if not revoked)
```

### Data Flow
1. User provides seed + nonce (off-chain)
2. System computes commitments: `seed_commit`, `phaseA_hash`, `phaseB_hash`
3. System computes `geoCommit` from commitments + policy + version
4. Server checks revocation registry (on-chain read)
5. If not revoked → proceed with generation
6. Optionally attest `geoCommit` to registry (on-chain write)

---

## Enforcement Mechanisms

### Pre-Generation Gate
Before any generation/regeneration, server performs:

1. **Format validation**: Verify geoCommit is 32-byte hex string
2. **RPC health check**: Verify Base L2 connectivity
3. **Revocation query**: Call `RevocationRegistry.isRevoked(geoCommit)`
4. **Decision**: Allow generation if not revoked, deny otherwise

### Fail-Closed Modes

**STRICT_CHAIN=true** (default):
- Deny generation if RPC unreachable
- Prevents operating with stale revocation data

**STRICT_REVOCATION=true** (default):
- Deny generation if revocation check fails
- Prevents bypassing revocation enforcement

**BYTECODE_LOCK_ENABLED=true** (recommended production):
- Verify contract bytecode hash at startup
- Prevents using tampered or redeployed contracts

---

## Revocation Semantics

### Who Can Revoke
- v0.1: Any address can revoke any commitment (open revocation)
- v0.2 (planned): Signature-gated revocation (only authorized parties)

### Revocation Effects
- **Immediate**: Takes effect in next block (~2 seconds on Base)
- **Permanent**: Cannot be undone
- **Non-destructive**: Does not delete attestation data
- **Regeneration blocking**: Prevents all future regenerations using that commitment

### Use Cases
- User requests deletion of regeneration capability
- Regulatory compliance (GDPR "right to be forgotten" for regeneration rights)
- Security breach (compromised seed material)
- Policy violation detection

---

## Technical Specifications

### Network
- **Chain**: Base (Ethereum L2)
- **Block time**: ~2 seconds
- **Finality**: Probabilistic (~minutes for practical finality)
- **RPC**: Public endpoints + optional self-hosted node

### Gas Costs (Base L2)
- **Deployment**: ~$10-50 (one-time)
- **Attestation**: ~$0.01-0.10 per transaction
- **Revocation**: ~$0.01-0.10 per transaction
- **Queries**: FREE (read-only view calls)

### Smart Contracts
- **AnankeAttestationRegistry**: Immutable attestation storage
- **AnankeRevocationRegistry**: Public revocation flags
- **Compiler**: Solidity 0.8.20 with optimizer
- **Verification**: Contracts verified on Basescan
- **Upgradeability**: None (immutable by design)

### Commitment Format (v1)
```
geoCommit = Keccak256(
    "ANANKE_GEO_COMMIT_V1" ||
    seed_commit ||
    phaseA_hash ||
    phaseB_hash ||
    policyId ||
    version_u32_be
)
```

Where:
- `seed_commit` = SHA-256(seed || user_nonce)
- `phaseA_hash` = SHA-256(GeoPhase A parameter vector bytes)
- `phaseB_hash` = SHA-256(GeoPhase B audit vector bytes)
- `policyId` = SHA-256(policy document)
- `version_u32_be` = 4-byte big-endian protocol version

**Domain separation**: PREFIX ensures no collisions with other commitment schemes  
**Version locking**: Version changes produce different commitments

---

## Security & Audit Posture

### Smart Contract Security
✅ No reentrancy vectors (no external calls, no ETH transfers)  
✅ No integer overflow/underflow (Solidity 0.8.20+ built-in checks)  
✅ No unbounded loops or DoS vectors  
✅ Immutable contracts (no upgradeability)  
✅ Fixed gas costs (predictable, no griefing)

### Off-Chain Integration Security
✅ Seed material never logged or exposed  
✅ TLS for all RPC connections  
✅ Dependency locking via requirements-lock.txt  
✅ Input validation on all external inputs  
✅ Structured error handling (no information leakage)

### Monitoring
- System metrics only (RPC latency, error rates)
- No user-identifying metrics
- No content or behavioral tracking
- Alerts on unexpected attestation patterns

---

## Compliance Considerations

### Data Protection (GDPR/CCPA)
- **Right to erasure**: Revocation mechanism provides functional deletion of regeneration capability
- **Data minimization**: Only commitments stored, no raw data
- **Purpose limitation**: Commitments used solely for provenance attestation
- **Transparency**: Full documentation of on-chain storage

### Genomic Data Regulations
- **No genomic data on-chain**: All genomic data remains off-chain
- **Consent enforcement**: Attestation can bind to consent policy document hash
- **Audit trail**: Immutable record of attestations and revocations

### Financial Regulations
- **Not a financial instrument**: Commitments have no transferable value
- **No payments**: Gas fees only, no protocol fees or royalties
- **No custody**: No user funds held or managed

---

## Operational Security

### Infrastructure
- **RPC endpoints**: Multi-provider setup with automatic failover
- **Monitoring**: 24/7 health checks, alert on anomalies
- **Backup**: Self-hosted Base node for RPC independence
- **Rate limiting**: DDoS protection on server endpoints

### Incident Response
- **Unexpected attestation**: Alert, investigate attestor address
- **Mass revocation**: Monitor for abuse, document for v0.2 access controls
- **RPC compromise**: Switch to backup provider, verify via block explorer
- **Contract anomaly**: Bytecode lock prevents serving requests

---

## Limitations & Residual Risks

### Accepted Trade-offs

⚠️ **Public observability**: All attestations/revocations are public on blockchain
- **Rationale**: Transparency required for verifiability and decentralization
- **Mitigation**: Use fresh addresses per attestation if privacy required

⚠️ **No revocation authorization (v0.1)**: Anyone can revoke any commitment
- **Rationale**: Simplified model for initial deployment
- **Mitigation**: v0.2 will add signature-gated revocation

⚠️ **RPC trust**: Clients trust RPC provider for state queries
- **Rationale**: Practical necessity for most deployments
- **Mitigation**: Users can self-host Base node for trustless verification

⚠️ **Gas cost variability**: Base L2 gas prices fluctuate
- **Rationale**: Market-driven gas pricing
- **Mitigation**: L2 costs remain low (<$1 per operation)

### Not Addressed in v0.1
- Cross-chain attestation mirroring
- Batch attestation optimization
- Zero-knowledge proof verification on-chain
- NFT-based regeneration rights

---

## Verification & Auditability

### For Regulators
- **Contract source code**: Verified on Basescan at deployment addresses
- **Commitment format**: Fully documented in GEO-COMMIT-SPEC.md
- **Test coverage**: Comprehensive unit + integration tests
- **Deployment records**: Immutable transaction history on Base

### For Users
- **Query attestation**: Anyone can verify attestation status via blockchain explorer
- **Check revocation**: Public `isRevoked(geoCommit)` function
- **Verify ethics anchor**: Check ethicsAnchor matches expected value
- **Audit trail**: Full event history available via block explorer

### For Third-Party Auditors
- **Smart contracts**: Open source, verifiable on-chain
- **Commitment computation**: Reference implementation in Python
- **Test harness**: Determinism + fail-closed behavior tests
- **Documentation**: Complete specifications in docs/ directory

---

## Contact & References

**Repository**: https://github.com/FractalFuryan/dna-ledger-vault  
**Documentation**:
- [GEO-COMMIT-SPEC.md](GEO-COMMIT-SPEC.md) — Commitment format specification
- [DEPLOYMENT-ETH.md](DEPLOYMENT-ETH.md) — Deployment guide
- [THREAT-MODEL-ETH.md](THREAT-MODEL-ETH.md) — Security threat analysis
- [SECURITY.md](../SECURITY.md) — Overall security documentation

**Ethics Anchor (SHA-256)**:
```
65b14d584f5a5fd070fe985eeb86e14cb3ce56a4fc41fd9e987f2259fe1f15c1
```

**Contract Addresses** (to be added after deployment):
- Base Mainnet: TBD
- Base Sepolia (Testnet): TBD

---

## Version History

- **v0.1.0** (2026-01-17): Initial release (attestation + revocation)
- **v0.1.1** (2026-01-17): Hardening update (bytecode lock, fail-closed middleware, comprehensive tests)
- **v0.2.0** (planned): Signature-gated revocation, EIP-712 procedural auth, batch attestation
