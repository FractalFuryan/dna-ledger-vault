# GeoPhase Commitment Specification

⭕️🛑 **Privacy-safe on-chain attestation**

This document specifies how GeoPhase commitments are computed for Ethereum attestation.

---

## Design Principles

1. **Commitment-only**: Store hashes on-chain, never raw data
2. **No media**: Never upload generated outputs to chain
3. **No likeness**: No user biometric or identifying data
4. **Revocable**: Allow commitment revocation without revealing data
5. **Verifiable**: Prove output authenticity without revealing seed

---

## Commitment Format

### Off-chain Computation

```python
seed_commit = SHA256(seed || user_nonce)
phase_a_hash = SHA256(phase_a_vector_bytes)
phase_b_hash = SHA256(phase_b_vector_bytes)
policy_id = SHA256(policy_document)
```

### On-chain Commitment

```
geoCommit = Keccak256(
  "ANANKE_GEO_COMMIT_V1" ||
  seed_commit ||
  phase_a_hash ||
  phase_b_hash ||
  policy_id ||
  version_u32
)
```

**Field sizes:**
- `seed_commit`: 32 bytes (SHA-256)
- `phase_a_hash`: 32 bytes (SHA-256)
- `phase_b_hash`: 32 bytes (SHA-256)
- `policy_id`: 32 bytes (SHA-256)
- `version`: 4 bytes (uint32, big-endian)

**Total commitment input:** Domain (20 bytes) + 32 + 32 + 32 + 32 + 4 = 152 bytes

---

## Attestation Structure

On-chain attestation stores:

```solidity
struct Attestation {
    bytes32 ethicsAnchor;  // SHA-256 of ethics invariants
    bytes32 policyId;      // SHA-256 of policy document
    uint32 version;        // Protocol version
    address attestor;      // Who attested
    uint64 timestamp;      // When attested
}
```

**Ethics Anchor:**
```
65b14d584f5a5fd070fe985eeb86e14cb3ce56a4fc41fd9e987f2259fe1f15c1
```

---

## Revocation

Any address can revoke a commitment by calling:

```solidity
RevocationRegistry.revoke(geoCommit)
```

Once revoked:
- Regeneration attempts must fail
- Existing outputs remain valid (non-destructive)
- Revocation is permanent and public

---

## Verification Flow

### Before Generation

1. Compute `geoCommit` from parameters
2. Check `RevocationRegistry.isRevoked(geoCommit)`
3. If revoked → abort
4. If not revoked → proceed with generation
5. Optionally attest on-chain after generation

### Verification by Third Party

1. Receive output + metadata (seed_commit, phase hashes, policy_id, version)
2. Compute `geoCommit` independently
3. Check `AttestationRegistry.isAttested(geoCommit)`
4. Verify `ethicsAnchor` matches expected value
5. Check `RevocationRegistry.isRevoked(geoCommit)`
6. If all pass → output is valid and non-revoked

---

## Privacy Guarantees

**What is revealed on-chain:**
- Commitment hash (reveals nothing about seed or parameters)
- Ethics anchor (public constant)
- Policy ID (public policy version)
- Attestor address
- Timestamp

**What is NOT revealed:**
- Seed value
- User nonce
- GeoPhase A/B parameter vectors
- Generated outputs
- User identity (unless linked via attestor address)

---

## Example Python Usage

```python
from geophase_eth import (
    compute_geo_commit,
    create_seed_commit,
    create_phase_hashes,
    sha256_hash,
    ChainGate,
)

# Create commitments
seed = b"random_seed_bytes"
nonce = b"user_nonce_12345"
seed_commit = create_seed_commit(seed, nonce)

phase_a = b"phase_a_vector_serialized"
phase_b = b"phase_b_vector_serialized"
phase_a_hash, phase_b_hash = create_phase_hashes(phase_a, phase_b)

policy_doc = b"policy_document_v1"
policy_id = sha256_hash(policy_doc)

# Compute on-chain commitment
geo_commit = compute_geo_commit(
    seed_commit=seed_commit,
    phase_a_hash=phase_a_hash,
    phase_b_hash=phase_b_hash,
    policy_id=policy_id,
    version=1,
)

# Check revocation before generation
gate = ChainGate(
    rpc_url="https://mainnet.base.org",
    revocation_address="0x...",
    attestation_address="0x...",
)

gate.check_before_generation(geo_commit)  # Raises if revoked
```

---

## Contract Addresses

### Base Mainnet (TBD)
- `AnankeAttestationRegistry`: TBD
- `AnankeRevocationRegistry`: TBD

### Base Sepolia (Testnet)
- `AnankeAttestationRegistry`: TBD
- `AnankeRevocationRegistry`: TBD

---

## Security Considerations

1. **Commitment binding**: Once attested, commitment is immutable
2. **Revocation finality**: Revocation is permanent, cannot be undone
3. **No privacy leakage**: Commitments are cryptographically hiding
4. **Front-running**: Attestation is public, anyone can observe commitments
5. **Rate limiting**: Consider rate limits on revocation to prevent spam

---

## References

- [DNA Ledger Vault Security](SECURITY.md)
- [Ethics Anchor](SECURITY.md#ethics-anchor)
- [GeoPhase Architecture](GEO-PHASE.md)
