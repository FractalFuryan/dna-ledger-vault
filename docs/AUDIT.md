# AUDIT.md — Compliance & Verification Guide

**DNA Ledger Vault** • Schema: `dna-ledger-vault/vNext.2`

This document provides auditors, reviewers, and compliance officers with:
1. Threat model summary
2. Security invariants (executable policy)
3. Verification commands
4. Evidence bundle instructions

---

## 1. Threat Model Summary

### Trust Assumptions
- **No trusted third party**: Owner controls their own keys
- **Malicious compute nodes**: Grantees may attempt unauthorized access or data leakage
- **Compromised storage**: Off-chain vault ciphertext may be copied/transplanted
- **Ledger integrity**: Append-only ledger provides tamper-evident audit trail

### Adversary Capabilities
- **Read access**: Adversary can read all ledger entries and vault ciphertexts
- **Network control**: Adversary can observe/delay/replay messages
- **Cryptanalysis**: Adversary cannot break Ed25519, X25519, ChaCha20-Poly1305, SHA-256

### Security Goals
1. **Confidentiality**: Plaintext DNA accessible only to authorized grantees with valid KeyWrapEvent
2. **Integrity**: Tampering with vault or ledger detectable via hash verification
3. **Provenance**: All ledger entries cryptographically signed (Ed25519)
4. **Consent enforcement**: Access requires active grant + no revocation + current wrap + not expired
5. **Forward secrecy**: Key rotation invalidates old DEKs, re-wrapping required
6. **Non-repudiation**: Signatures bind actions to identities
7. **Auditability**: Complete audit trail with Merkle inclusion proofs

---

## 2. Security Invariants

**All 8 invariants are executable in `tests/test_invariants.py`**.

Run with:
```bash
pytest tests/test_invariants.py -v
```

### Invariant 1: Append-Only Ledger
- **Property**: No payload mutation; all IDs unique
- **Test**: `test_no_duplicate_grant_ids`, `test_no_payload_mutation`
- **Enforcement**: KeyWrapEvent model replaces grant mutation during rotation

### Invariant 2: Full Block Header Hashing
- **Property**: `block_hash = h_block({prev, payload, signer, sig})`
- **Test**: `test_ledger_chain_integrity`, `test_signature_included_in_block_hash`
- **Enforcement**: `ledger.verify()` checks both chain and signatures

### Invariant 3: Domain-Separated Hashing
- **Property**: All hash functions use domain-specific prefixes
- **Test**: `test_domain_separation_in_merkle`, `test_domain_separation_prefixes`
- **Enforcement**: `h_leaf`, `h_node`, `h_payload`, `h_block`, `h_commit`

### Invariant 4: Dataset Commit Binding
- **Property**: `ConsentGrant.dataset_commit_hash == DatasetCommit.commit_hash`
- **Test**: `test_grant_bound_to_commit_hash`
- **Enforcement**: Grants locked to specific dataset versions

### Invariant 5: Wrap State Enforcement
- **Property**: Post-rotation access requires current KeyWrapEvent
- **Test**: `test_rotation_requires_key_wrap_event`, `test_revocation_blocks_access`
- **Enforcement**: `active_grants() + has_current_wrap() + !revoked`

### Invariant 6: Vault AAD Binding
- **Property**: Ciphertext authenticated with `{dataset_id, chunk_idx, merkle_root, owner, created_utc}`
- **Test**: `test_vault_aad_prevents_transplant`
- **Enforcement**: ChaCha20-Poly1305 AEAD with AAD

### Invariant 7: Signature Versioning
- **Property**: Signer includes algorithm identifier (`ed25519_pub_pem_b64`)
- **Test**: `test_signature_includes_algorithm_identifier`
- **Enforcement**: Future-proofs for algorithm migration

### Invariant 8: Merkle Inclusion Proofs
- **Property**: Chunk-level verification without full dataset
- **Test**: `test_merkle_proof_verification`, `test_merkle_proof_rejects_invalid`
- **Enforcement**: `merkle_proof()` + `verify_merkle_proof()`

---

## 3. Verification Commands

### Verify Ledger Integrity
```bash
python -m cli.main verify --out state
```

**Expected output**:
```
✅ Ledger OK (chain + signatures valid)
```

**Verifies**:
- Hash chain integrity (prev_hash linkage)
- Ed25519 signature validity for all blocks
- Schema version compliance (no downgrades)

### Verify Specific Dataset Commit
```bash
# Get commit hash for dataset
grep -A5 '"kind":"DatasetCommit"' state/ledger.jsonl | grep commit_hash

# Recompute and compare
python -c "
from dna_ledger.hashing import h_commit, merkle_root, h_leaf
import json

# Load commit from ledger
with open('state/ledger.jsonl') as f:
    for line in f:
        block = json.loads(line)
        if block['payload']['kind'] == 'DatasetCommit':
            commit = block['payload']
            break

# Verify commit hash
expected = h_commit({
    'dataset_id': commit['dataset_id'],
    'owner': commit['owner'],
    'merkle_root': commit['merkle_root'],
    'bytes': commit['bytes']
})

assert commit['commit_hash'] == expected, 'Commit hash mismatch!'
print(f'✅ Commit hash verified: {expected[:16]}...')
"
```

### Verify Merkle Inclusion Proof
```bash
# Export evidence bundle first
python -m cli.main export-evidence \
  --out state \
  --dataset-id <DATASET_ID> \
  --bundle-dir evidence_bundle \
  --actor owner

# Verify specific chunk proof
python -c "
import json
from dna_ledger.merkle_proof import verify_merkle_proof

# Load proof
with open('evidence_bundle/proofs/chunk_0000_proof.json') as f:
    proof_data = json.load(f)

is_valid = verify_merkle_proof(
    proof_data['leaf_hash'],
    proof_data['chunk_index'],
    proof_data['proof'],
    proof_data['merkle_root']
)

assert is_valid, 'Merkle proof invalid!'
print('✅ Merkle proof verified for chunk 0')
"
```

### Verify Consent Policy Enforcement
```bash
# Check if grant active and not revoked
python -c "
import json, time

blocks = []
with open('state/ledger.jsonl') as f:
    for line in f:
        blocks.append(json.loads(line))

payloads = [b['payload'] for b in blocks]

# Find grant
grant = next(p for p in payloads if p.get('grant_id') == '<GRANT_ID>')

# Check expiration
now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
assert grant['expires_utc'] > now, 'Grant expired!'

# Check revocation
revoked = any(
    p.get('kind') == 'ConsentRevocation' and p.get('grant_id') == grant['grant_id']
    for p in payloads
)
assert not revoked, 'Grant revoked!'

# Check current wrap (post-rotation)
latest_rotation = [p for p in payloads 
                   if p.get('kind') == 'KeyRotationEvent' 
                   and p['dataset_id'] == grant['dataset_id']]
rot_id = latest_rotation[-1]['rotation_id'] if latest_rotation else 'initial'

has_wrap = any(
    p.get('kind') == 'KeyWrapEvent'
    and p['dataset_id'] == grant['dataset_id']
    and p['grantee'] == grant['grantee']
    and p['rotation_id'] == rot_id
    for p in payloads
)
assert has_wrap, 'No current wrap for latest rotation!'

print('✅ Grant policy verified (active + !revoked + current wrap)')
"
```

---

## 4. Evidence Bundle Instructions

### Export Evidence Bundle

For regulators, journal reviewers, or partner labs:

```bash
# Export all ledger events
python -m cli.main export-evidence \
  --out state \
  --bundle-dir compliance_evidence \
  --actor owner

# Export for specific dataset (includes Merkle proofs)
python -m cli.main export-evidence \
  --out state \
  --dataset-id ds_abc123 \
  --bundle-dir dataset_evidence \
  --actor owner
```

### Bundle Contents

**Complete bundle includes**:

1. **`evidence.json`**:
   - Schema version: `dna-ledger-vault/vNext.2`
   - Exported timestamp
   - Signer identity
   - All ledger blocks (or filtered by dataset)
   - Ledger tip hash (latest block hash)

2. **`evidence.sig`**:
   - Ed25519 signature over `evidence.json`
   - Signer's public key
   - Signature timestamp

3. **`proofs/`** (if dataset specified):
   - Merkle inclusion proof for each chunk
   - Format: `chunk_NNNN_proof.json`
   - Contains: leaf hash, index, proof path, merkle root

### Verify Evidence Bundle

Recipient can verify authenticity:

```bash
python -c "
import json, base64
from dna_ledger.signing import verify_payload

# Load evidence
with open('evidence.json') as f:
    evidence = json.load(f)

# Load signature
with open('evidence.sig') as f:
    sig_data = json.load(f)

# Verify signature
ed_pub = base64.b64decode(sig_data['ed25519_pub_pem_b64'])
is_valid = verify_payload(evidence, sig_data['signature_b64'], ed_pub)

assert is_valid, 'Signature verification failed!'
print(f\"✅ Evidence bundle verified (signed by {sig_data['signer']})\")
print(f\"   Schema: {evidence['schema']}\")
print(f\"   Blocks: {evidence['block_count']}\")
print(f\"   Ledger tip: {evidence['ledger_tip'][:16]}...\")
"
```

---

## 5. Cryptographic Specifications

### Algorithms
- **Encryption**: ChaCha20-Poly1305 (AEAD)
  - Key size: 256 bits
  - Nonce size: 96 bits (random per chunk)
  - AAD: `{dataset_id, chunk_idx, merkle_root, owner, created_utc}`
  
- **Signatures**: Ed25519
  - Public key size: 256 bits
  - Signature size: 512 bits
  - Deterministic (RFC 8032)

- **Key Wrapping**: X25519 ECDH + HKDF-SHA256
  - Ephemeral X25519 keypair per wrap
  - HKDF info: `"dek-wrap"`
  - Output: 256-bit symmetric key for ChaCha20-Poly1305

- **Hashing**: SHA-256
  - Domain separation prefixes: `LEAF`, `NODE`, `PAYLOAD`, `BLOCK`, `COMMIT`
  - Merkle tree construction: binary tree with domain-separated nodes

### Key Management
- **Owner**: Ed25519 (signing) + X25519 (wrapping)
- **Grantee**: Ed25519 (signing) + X25519 (unwrapping)
- **DEK**: 256-bit random key (per dataset)
- **Rotation**: New DEK generated, old grants require re-wrapping via KeyWrapEvent

---

## 6. Compliance Checklist

For auditors reviewing this implementation:

- [ ] **Invariant tests pass**: `pytest tests/test_invariants.py -v`
- [ ] **Ledger verifies**: `python -m cli.main verify --out state`
- [ ] **Schema enforcement**: All payloads include `schema: dna-ledger-vault/vNext.2`
- [ ] **Domain separation**: All hashes use proper prefixes
- [ ] **Append-only semantics**: No grant mutation during rotation
- [ ] **Policy enforcement**: Attestation requires active grant + current wrap + !revoked
- [ ] **Merkle proofs work**: Chunk verification without full dataset
- [ ] **Evidence bundles**: Export/verify compliance packets
- [ ] **Dependencies pinned**: `requirements.txt` specifies version bounds
- [ ] **SECURITY.md complete**: All invariants documented

---

## 7. Contact & References

**Security Invariants**: [SECURITY.md](SECURITY.md#invariants)  
**Demo Workflow**: [DEMO.md](DEMO.md)  
**README**: [README.md](README.md)

**Schema Version**: `dna-ledger-vault/vNext.2`  
**Last Updated**: 2026-01-04

For security issues or audit questions, see repository maintainers.
