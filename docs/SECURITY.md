# Security Architecture 🔐

This document explains the cryptographic invariants and security properties of `dna-ledger-vault`.

---

## 🔒 SECURITY INVARIANTS (Audit-Grade)

These are the **non-negotiable properties** that the system enforces. Any violation indicates compromise or implementation error.

### 1. Append-Only Ledger
**Invariant:** Ledger entries are never modified or deleted. All state changes emit new events.
- ✅ Consent grants are never mutated
- ✅ Revocations emit explicit `ConsentRevocation` events
- ✅ Key rotation emits `KeyRotationEvent` + N×`KeyWrapEvent`
- ❌ **VIOLATION:** Rewriting, deleting, or updating historical entries

### 2. Block Hash Covers Full Header
**Invariant:** `block_hash = H_BLOCK(prev_hash || payload || signer || sig)`
- ✅ Prevents swapping signer metadata while keeping chain valid
- ✅ Domain-separated hash (`H_BLOCK`) prevents structural collisions
- ❌ **VIOLATION:** Block hash not covering signature/signer

### 3. Domain-Separated Hashing
**Invariant:** All hash operations use domain separation to prevent reinterpretation attacks.
- `H_LEAF(chunk)` = `SHA256("DNALEAF\x00" || chunk)`
- `H_NODE(L, R)` = `SHA256("DNANODE\x00" || L || R)`
- `H_PAYLOAD(p)` = `SHA256("PAYLOAD\x00" || canonical(p))`
- `H_BLOCK(b)` = `SHA256("BLOCK\x00" || canonical(b))`
- `H_COMMIT(c)` = `SHA256("DATASETCOMMIT\x00" || canonical(c))`
- ❌ **VIOLATION:** Using raw `SHA256(data)` without domain prefix

### 4. Consent Validity Conditions
**Invariant:** Compute attestation allowed ⟺ ALL of:
1. Active `ConsentGrant` exists for `(dataset_id, grantee, purpose, dataset_commit_hash)`
2. Grant is **not revoked** (`ConsentRevocation` does not exist for `grant_id`)
3. Grant is **not expired** (`expires_utc > now()`)
4. Grantee has `KeyWrapEvent` for **current rotation** (or "initial" if no rotation)

- ❌ **VIOLATION:** Attesting without valid consent
- ❌ **VIOLATION:** Attesting with revoked or expired grant
- ❌ **VIOLATION:** Attesting without current `KeyWrapEvent`

### 5. Post-Rotation Access Control
**Invariant:** After key rotation, access requires current `KeyWrapEvent`.
- `latest_rotation(dataset_id)` returns most recent `rotation_id`
- Grantee must have `KeyWrapEvent` matching `rotation_id`
- Revoked grantees do NOT receive new `KeyWrapEvent` (permanently excluded)
- ❌ **VIOLATION:** Accepting stale wraps from previous rotations

### 6. Dataset Commit Binding
**Invariant:** Consent grants bind to specific dataset versions via `dataset_commit_hash`.
- `commit_hash = H_COMMIT(DatasetCommit)`
- `ConsentGrant.dataset_commit_hash` must match committed dataset
- ❌ **VIOLATION:** Grant not bound to specific commit
- ❌ **VIOLATION:** Reusing grant for different dataset version

### 7. Vault AAD Binding
**Invariant:** Vault ciphertext AAD binds to `(dataset_id, commit_hash, vault_schema)`.
- AAD = `canonical({"dataset_id": "...", "commit_hash": "...", "vault_schema": "vault/v1"})`
- Prevents ciphertext reuse across datasets
- ❌ **VIOLATION:** Decrypting with mismatched AAD
- ❌ **VIOLATION:** AAD not including commit_hash

### 8. Signature Covers Versioned Payload
**Invariant:** Signatures include schema version to prevent reinterpretation.
- Sign: `{"schema": "dna-ledger-vault/payload/v1", "payload": <data>}`
- ❌ **VIOLATION:** Signing raw payload without schema version (future work)

---

## Core Principle: DNA Never Touches The Ledger

**Threat:** DNA sequences are inherently identifying. Storing them on any shared ledger (blockchain or otherwise) creates irreversible privacy loss.

**Mitigation:** This system uses a **vault + ledger split architecture**:
- **Vault (off-chain):** Encrypted DNA datasets (ChaCha20-Poly1305 AEAD)
- **Ledger (on-chain):** Only hashes, consent records, and attestations

Raw genomic data never leaves the encrypted vault.

---

## Security Layers

### 1. Hash Chain Integrity (Tamper Evidence)

Each ledger block contains:
```
block = {
  prev_hash: sha256 of previous block
  payload: {dataset commit | consent grant | revocation | attestation}
  signer: {id, ed25519_pub_pem_b64}
  sig: ed25519 signature over payload
  block_hash: sha256(prev_hash || canonical(payload))
}
```

**Invariant:** Any modification to historical entries breaks the chain.

**Verification:**
```python
def verify():
    prev = sha256(b"GENESIS")
    for block in ledger:
        assert block.prev_hash == prev
        assert block.block_hash == sha256(prev + canonical(payload))
        prev = block.block_hash
```

---

### 2. Cryptographic Provenance (Ed25519 Signatures)

Every payload is signed by its creator using Ed25519.

**Properties:**
- **Non-repudiation:** Signer cannot deny creating the entry
- **Authenticity:** Verifier knows who created each record
- **Integrity:** Signature verification detects tampering

**Key generation:**
```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

priv = Ed25519PrivateKey.generate()
pub = priv.public_key()
```

**Signing:**
```python
sig = priv.sign(canonical(payload))  # 64 bytes
```

**Verification:**
```python
pub.verify(sig, canonical(payload))  # raises if invalid
```

**Ledger verification checks both:**
1. Hash chain continuity ✓
2. Signature validity on every block ✓

---

### 3. Vault Encryption (ChaCha20-Poly1305 AEAD)

DNA datasets are encrypted with **authenticated encryption** (AEAD).

**Construction:**
- **Algorithm:** ChaCha20-Poly1305 (IETF standard)
- **Key:** 256-bit DEK (data encryption key), generated per dataset
- **Nonce:** 96-bit random (unique per encryption)
- **AAD:** Additional authenticated data (binds dataset ID + hash)

**Encryption:**
```python
aead = ChaCha20Poly1305(dek)
nonce = os.urandom(12)
ciphertext = aead.encrypt(nonce, plaintext, aad)
sealed_blob = nonce || ciphertext
```

**Properties:**
- **Confidentiality:** Plaintext hidden without DEK
- **Authenticity:** Tampering detected via MAC
- **Context binding:** AAD ties ciphertext to specific dataset

**Decryption:**
```python
nonce, ct = blob[:12], blob[12:]
plaintext = aead.decrypt(nonce, ct, aad)  # raises on tampering
```

---

### 4. Access Control (X25519 Key Wrapping)

DEKs are **wrapped** (encrypted) to grantee public keys using Diffie-Hellman key agreement.

**Protocol:**
1. Owner has X25519 keypair `(priv_owner, pub_owner)`
2. Grantee has X25519 keypair `(priv_grantee, pub_grantee)`
3. Compute ECDH shared secret: `shared = priv_owner ⊗ pub_grantee`
4. Derive wrap key: `wrap_key = HKDF-SHA256(shared, context)`
5. Encrypt DEK: `wrapped_dek = ChaCha20Poly1305(wrap_key).encrypt(dek)`

**Key properties:**
- **No shared secrets:** Owner and grantee never exchange keys directly
- **Forward secrecy:** Compromise of long-term keys doesn't reveal past DEKs
- **Context binding:** `context` includes dataset_id + purpose + grantee identity

**Unwrapping (by grantee):**
```python
shared = priv_grantee ⊗ pub_owner
wrap_key = HKDF-SHA256(shared, context)
dek = ChaCha20Poly1305(wrap_key).decrypt(wrapped_dek)
```

**Security guarantee:** Only the intended grantee can unwrap the DEK.

---

### 5. Policy Enforcement (Consent Verification)

Before recording a compute attestation, the system verifies:

```python
def can_attest(actor, dataset_id, purpose):
    grants = active_grants(ledger, dataset_id, purpose)
    for grant in grants:
        if grant.grantee == actor:
            if grant.expires_utc > now():
                if not is_revoked(grant.grant_id):
                    return True
    return False
```

**Enforced conditions:**
1. ✅ Grant exists for (dataset, actor, purpose)
2. ✅ Grant not expired
3. ✅ Grant not revoked

**Violation result:** Attestation rejected (not recorded on ledger).

---

### 6. Revocation (Explicit On-Chain Truth)

Consent can be revoked via explicit ledger events:

```python
ConsentRevocation {
    grant_id: "cg_...",
    reason: "study completed",
    created_utc: "2026-01-04T..."
}
```

**Properties:**
- **Explicit:** No ambiguity (revocation event on-chain)
- **Auditable:** Timestamp + reason recorded
- **Immediate:** Policy checks see revocation instantly

**Effect:** Revoked grants fail `active_grants()` check.

---

### 7. Key Rotation (Forward Secrecy)

Periodic DEK rotation provides **forward secrecy** and **post-compromise safety**.

**Rotation process:**
1. Generate new DEK
2. Decrypt dataset with old DEK
3. Re-encrypt dataset with new DEK
4. Re-wrap new DEK to **active grantees only** (excludes revoked)
5. Record `KeyRotationEvent` on ledger
6. Discard old DEK

**Security guarantees:**
- **Forward secrecy:** Compromise of old DEK doesn't affect post-rotation data
- **Post-compromise safety:** If DEK leaks, rotation limits exposure window
- **Automatic re-authorization:** Only current active grantees get new DEK

**Revoked users:** Do not receive new wrapped DEK (permanently excluded).

---

## Threat Model Summary

| Threat | Mitigation |
|--------|-----------|
| DNA leakage on ledger | Vault + ledger split (only hashes on-chain) |
| Ledger tampering | Hash chain + Ed25519 signatures |
| Unauthorized access | X25519 key wrapping + policy enforcement |
| Consent ambiguity | Explicit on-chain grants + revocations |
| Key compromise | Rotation with forward secrecy |
| Replay attacks | Nonce + AAD binding in AEAD |
| Timestamp manipulation | Signed ledger entries with UTC timestamps |

---

## Cryptographic Assumptions

This system relies on:

1. **Ed25519** (EdDSA): Secure signatures (Curve25519)
2. **X25519** (ECDH): Secure key agreement (Curve25519)
3. **SHA-256**: Collision-resistant hashing
4. **ChaCha20-Poly1305**: Authenticated encryption (IETF RFC 8439)
5. **HKDF-SHA256**: Key derivation (RFC 5869)

All primitives use **well-vetted implementations** from Python's `cryptography` library.

---

## Audit Trail Properties

Every ledger entry is:
- **Hash-chained** (tamper-evident)
- **Signed** (provenance)
- **Timestamped** (auditable sequence)
- **Immutable** (append-only)

Query examples:
```python
# Who committed dataset X?
commits = ledger.find_by("dataset_id", "ds_...")
owner = commits[0]["signer"]["id"]

# When was consent granted to researcher Y?
grants = [b for b in ledger if b["payload"]["grantee"] == "researcher_Y"]

# Was consent revoked?
revocations = [b for b in ledger if b["payload"]["kind"] == "ConsentRevocation"]
```

---

## Operational Security Notes

### Key Management
- **Identity keys:** Store Ed25519 + X25519 private keys securely (HSM in production)
- **DEKs:** Never log or expose plaintext DEKs
- **Wrapped DEKs:** Safe to store (only unwrappable by grantee)

### Ledger Storage
- Current implementation: Local JSONL file
- Production: Replace with append-only database or blockchain
- Verification: Run `verify()` periodically

### Vault Storage
- Current implementation: Local encrypted files
- Production: Use encrypted object storage (S3 + KMS, etc.)
- Backup: Encrypted vault blobs are safe to replicate

---

## Future Enhancements

### Merkle Inclusion Proofs
Prove specific dataset chunks without revealing full dataset.

### Zero-Knowledge Proofs
"Prove SNP marker present" without disclosing genome sequence.

### Smart Contract Deployment
Replace local ledger with Ethereum/Solana for decentralized verification.

---

## Security Disclosures

**Found a vulnerability?** Contact: [your-contact-method]

**Out of scope:**
- Side-channel attacks on local key storage
- Timing attacks (mitigated by constant-time crypto primitives)
- Physical access to vault storage

---

**Last updated:** January 4, 2026  
**Version:** vNext.1 (Revocation + Key Rotation)
