# RFC6979 Nonce Generation Policy

**Version:** 1.0  
**Last Updated:** January 18, 2026  
**Status:** Production

---

## Executive Summary

This document defines the **RFC6979 deterministic nonce generation policy** for ECDSA signatures in the DNA Ledger Vault project.

**Key Principle:**  
> The `extra` parameter is for **domain separation only**, not entropy injection.

All nonce randomness comes exclusively from RFC6979's HMAC-DRBG chain. We do **not** introduce custom entropy sources into signature nonce generation.

---

## 1. Background: Why RFC6979?

### The ECDSA Nonce Problem

Standard ECDSA requires a random nonce `k` for each signature:

```
r = (k × G).x mod n
s = k⁻¹(z + r × privkey) mod n
```

**If `k` is:**
- **Reused** → Private key can be recovered
- **Biased** → Private key can be recovered via lattice attacks
- **Predictable** → Private key can be recovered

**RFC6979 Solution:**  
Generate `k` deterministically using HMAC-DRBG:

```
k = HMAC-DRBG(privkey, message_hash, extra_data)
```

This eliminates:
- Random number generator failures
- Nonce reuse bugs
- Timing attacks on RNG
- Need for high-quality entropy sources

---

## 2. Implementation Details

### 2.1 Nonce Generation Function

```python
def rfc6979_generate_k(
    priv_int: int,
    hash_bytes: bytes,
    extra: bytes = b"",
) -> int
```

**Inputs:**
- `priv_int`: Private key (integer in [1, n-1])
- `hash_bytes`: Message hash (SHA-256 digest, 32 bytes)
- `extra`: Domain separation data (optional, **not entropy**)

**Process:**
1. Initialize HMAC state: `V = 0x01...`, `K = 0x00...`
2. Mix in private key: `bx = int2octets(priv_int)`
3. Mix in message hash: `bh = bits2octets(hash_bytes)`
4. Mix in domain tag: `extra_h = SHA-256(extra)` (if provided)
5. HMAC update: `K = HMAC_K(V || 0x00 || bx || bh || extra_h)`
6. Generate candidate `k` via HMAC chain
7. **Reject and retry** if `k ∉ [1, n-1]` (no modulo bias)
8. Return valid `k`

**Output:**
- Deterministic nonce `k` in [1, n-1]

---

### 2.2 Low-S Normalization

After generating signature `(r, s)`, we normalize to **canonical low-S form**:

```python
if s > n // 2:
    s = n - s
```

**Why?**
- Bitcoin (BIP 146) and Ethereum require `s ≤ n/2`
- Prevents signature malleability attacks
- Ensures canonical signature representation

---

## 3. Domain Separation via `extra`

### 3.1 What is Domain Separation?

Domain separation binds signatures to **application context** without affecting security.

**Example use cases:**
- Protocol version tags
- Commitment metadata
- Policy identifiers
- Network identifiers

**NOT for:**
- Adding entropy
- "Improving randomness"
- Steering nonce generation
- Creating custom DRBGs

---

### 3.2 Safe `extra` Usage Patterns

#### ✅ **CORRECT: Commitment Metadata**

```python
# Bind signature to GeoPhase commitment
commitment_hash = hashlib.sha256(
    b"GRAIL|" + food_hash + b"|t2|" + text.encode() + b"|M|" + str(prime).encode()
).digest()

extra = b"ZETA_SNAKE_TETRIS_V1|" + commitment_hash
sig = sign_with_rfc6979(priv_int, msg, extra=extra)
```

**Properties:**
- Deterministic (same inputs → same signature)
- Auditable (commitment hash is public)
- Non-secret (extra is not a key)
- Domain-separated (different protocols → different sigs)

---

#### ✅ **CORRECT: Version Tagging**

```python
extra = b"DNA_LEDGER_VAULT_V1"
sig = sign_with_rfc6979(priv_int, msg, extra=extra)
```

---

#### ❌ **WRONG: Custom Entropy Injection**

```python
# DON'T DO THIS
random_bytes = os.urandom(32)
extra = b"RANDOM|" + random_bytes  # ← Breaks determinism!
sig = sign_with_rfc6979(priv_int, msg, extra=extra)
```

**Why wrong?**
- Defeats RFC6979 determinism
- Reintroduces RNG failure risks
- Makes signatures non-reproducible
- Audit trail becomes unclear

---

#### ❌ **WRONG: Secret Material**

```python
# DON'T DO THIS
extra = secret_key  # ← Never mix secrets into extra!
```

**Why wrong?**
- `extra` is not a key input
- Leaking `extra` should not compromise security
- Creates confusion about threat model

---

## 4. Security Properties

### 4.1 Determinism

**Property:**  
Same `(privkey, message, extra)` → Same signature

**Implications:**
- Signatures are reproducible
- Audit trails are verifiable
- No hidden state or randomness

**Caveat:**  
If you need per-event uniqueness, include a nonce **in the message**, not in `extra`.

---

### 4.2 Nonce Safety

**Guarantee:**  
Nonce `k` is never reused for different messages (same privkey).

**Proof sketch:**
- `k = HMAC(privkey, message_hash, extra)`
- Different `message_hash` → Different `k`
- HMAC is collision-resistant
- Therefore: `k` collision implies SHA-256 collision

---

### 4.3 Domain Separation

**Property:**  
Changing `extra` produces different signatures for the same message.

**Use case:**
- Prevent cross-protocol signature replay
- Bind signatures to application context
- Separate test vs production signatures

**Example:**
```python
# Production signature
sig_prod = sign_with_rfc6979(priv, msg, b"PROD_V1")

# Test signature (different domain)
sig_test = sign_with_rfc6979(priv, msg, b"TEST_V1")

assert sig_prod != sig_test  # Same message, different domains
```

---

## 5. Integration with DNA Ledger Vault

### 5.1 Current Usage

**Ed25519 (primary):**
- Uses `dna_ledger/signing.py` (Ed25519)
- Already deterministic (RFC 8032)
- No nonce generation issues
- **No changes needed**

**secp256k1 (Ethereum bridge):**
- Uses `dna_ledger/rfc6979.py` (this implementation)
- For Ethereum/Base L2 signatures
- EIP-712 typed data signing
- Commitment attestations

---

### 5.2 Recommended Extra Format

For GeoPhase attestations:

```python
def build_attestation_extra(
    protocol_version: str,
    commitment_hash: bytes,
) -> bytes:
    """
    Build domain separation tag for attestation signatures.
    
    Format: "DNA_LEDGER_VAULT|v{version}|{commitment_hex}"
    """
    commitment_hex = commitment_hash.hex()
    tag = f"DNA_LEDGER_VAULT|v{protocol_version}|{commitment_hex}"
    return tag.encode("utf-8")
```

---

## 6. Testing Strategy

### 6.1 Test Vectors

**Must verify:**
1. **RFC6979 compliance** (test vectors from RFC)
2. **Determinism** (same inputs → same output)
3. **Domain separation** (different `extra` → different sig)
4. **Low-S normalization** (all `s ≤ n/2`)
5. **Rejection sampling** (no modulo bias, valid `k` range)

---

### 6.2 Audit Requirements

**For external review, provide:**
- Test vector logs (inputs + outputs)
- Nonce generation trace (HMAC states for sample run)
- Signature verification (round-trip test)
- Domain separation proof (colliding messages with different `extra`)

---

## 7. Failure Modes & Mitigations

| Failure Mode | Risk | Mitigation |
|--------------|------|------------|
| RNG failure | N/A (deterministic) | RFC6979 eliminates RNG dependency |
| Nonce reuse | N/A (deterministic) | HMAC ensures different k per message |
| Modulo bias | Low | Rejection sampling (retry if k out of range) |
| Signature malleability | Medium | Low-S normalization enforced |
| Cross-protocol replay | Medium | Domain separation via `extra` |
| Extra data leak | Low | `extra` is non-secret by design |

---

## 8. References

- **RFC 6979:** Deterministic Usage of DSA and ECDSA  
  https://datatracker.ietf.org/doc/html/rfc6979

- **BIP 146:** Dealing with signature encoding malleability  
  https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki

- **SEC1 v2.0:** Elliptic Curve Cryptography  
  https://www.secg.org/sec1-v2.pdf

- **FIPS 186-4:** Digital Signature Standard  
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

---

## 9. Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-18 | 1.0 | Initial policy document |

---

## 10. Approval

**Reviewed by:** DNA Ledger Vault Engineering  
**Status:** Approved for production use  
**Next Review:** Q3 2026 or upon significant cryptographic findings

---

**END OF DOCUMENT**
