# Cryptographic Upgrade Path 🔐

This document outlines the forward-compatible cryptographic upgrade strategy for dna-ledger-vault.

## Current Implementation (vNext.2)

**Status:** ✅ Audit-grade, production-ready

### Primitives
- **Vault AEAD:** ChaCha20-Poly1305 (96-bit nonce)
- **Key Wrapping:** X25519-ECDH + HKDF-SHA256 + ChaCha20-Poly1305
- **Signatures:** Ed25519
- **Hashing:** SHA-256 (canonical) + BLAKE3 (supplemental)

### Scheme Versioning
```python
wrap_scheme: "x25519-hkdf-chacha20poly1305-v1"
hash_scheme: "dual"  # SHA-256 + BLAKE3
aead_scheme: "chacha20poly1305-v1"  # implicit in vault
sig_scheme: "ed25519-v1"  # implicit in ledger
```

### Nonce Safety Guarantee

ChaCha20-Poly1305's 96-bit nonces are **cryptographically safe** under our design:

1. **Key-per-dataset isolation:** Each dataset gets unique DEK, never shared
2. **Key rotation on revocation:** Fresh DEK generated, old one discarded
3. **AAD binding:** Ciphertext tied to `(dataset_id, commit_hash, vault_schema)`
4. **Cryptographic RNG:** `os.urandom()` provides unpredictable nonces

**Collision probability:** 
- Birthday bound: 2^48 encryptions per key before 50% collision risk
- Our limit: ~1 key rotation per dataset (far below threshold)
- **Verdict:** No practical nonce reuse risk

---

## Future Upgrade: XChaCha20-Poly1305 (vNext.3)

**Target:** When Python `cryptography` library adds XChaCha20-Poly1305 support

### Benefits
- **192-bit nonces:** Eliminates theoretical nonce-reuse concerns
- **Operational safety:** More forgiving of implementation errors
- **Same performance:** ChaCha20 variant, no speed penalty

### Migration Strategy

1. **Update dependency:**
   ```toml
   cryptography >= X.Y.Z  # version with XChaCha20Poly1305
   ```

2. **Add new AEAD scheme:**
   ```python
   # vault/crypto.py
   from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
   
   NONCE_LEN = 24  # 192-bit nonce
   
   def seal_bytes(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
       aead = XChaCha20Poly1305(key)
       nonce = os.urandom(24)  # extended nonce
       ct = aead.encrypt(nonce, plaintext, aad)
       return nonce + ct
   ```

3. **Update models:**
   ```python
   aead_scheme: str = "xchacha20poly1305-v1"
   ```

4. **Backward compatibility:**
   - Old vaults (ChaCha20) remain readable
   - New vaults use XChaCha20
   - Scheme field determines decryption path

**Status:** 🕒 Waiting for upstream library support

---

## Future Upgrade: HPKE Wrapping (vNext.4)

**Target:** When Python `cryptography` library adds HPKE (RFC 9180) support

### Benefits
- **Standardized construction:** No hand-rolled KEM+KDF+AEAD composition
- **Formal security proofs:** HPKE has rigorous cryptographic analysis
- **Context binding:** Built-in `info` parameter for domain separation

### Migration Strategy

1. **Check library support:**
   ```python
   from cryptography.hazmat.primitives.asymmetric import hpke
   ```

2. **Add new wrap scheme:**
   ```python
   # vault/hpke_wrap.py
   def wrap_dek_hpke(grantee_pub_pem, dek, context):
       suite = hpke.CipherSuite.new(
           hpke.KEMId.DHKEM_X25519_HKDF_SHA256,
           hpke.KDFId.HKDF_SHA256,
           hpke.AEADId.CHACHA20_POLY1305,
       )
       enc, sender = suite.create_sender_context(grantee_pub, info=context)
       ct = sender.seal(aad=context, data=dek)
       return base64.b64encode(enc + ct).decode()
   ```

3. **Update models:**
   ```python
   wrap_scheme: str = "hpke-x25519-hkdfsha256-chacha20poly1305-v1"
   ```

4. **Dispatcher pattern:**
   ```python
   # vault/wrap.py
   def wrap_dek_dispatch(scheme, **kwargs):
       if scheme.startswith("hpke-"):
           return wrap_dek_hpke(**kwargs)
       else:
           return wrap_dek_legacy(**kwargs)
   ```

**Status:** 🕒 Waiting for upstream library support

---

## Future Upgrade: PQ-Hybrid Wrapping (vNext.5+)

**Target:** Post-quantum security with backward compatibility

### Benefits
- **Quantum resistance:** Protects against future quantum computers
- **Hybrid safety:** Classical X25519 + PQ KEM (both must break)
- **ML-KEM (Kyber):** NIST-standardized PQ algorithm

### Migration Strategy

1. **Add optional dependency:**
   ```toml
   [project.optional-dependencies]
   pq = ["oqs>=0.10.0"]  # Open Quantum Safe
   ```

2. **Hybrid KEM construction:**
   ```python
   # vault/pq_wrap.py
   def wrap_dek_hybrid(owner_x25519_priv, grantee_x25519_pub, 
                       grantee_mlkem_pub, dek, context):
       # Classical secret
       ss1 = owner_x25519_priv.exchange(grantee_x25519_pub)
       
       # PQ secret (ML-KEM-768)
       with oqs.KeyEncapsulation("ML-KEM-768") as kem:
           kem_ct, ss2 = kem.encap_secret(grantee_mlkem_pub)
       
       # Combine secrets
       wrap_key = HKDF(ss1 || ss2, context)
       
       # Wrap with XChaCha20-Poly1305
       aead = XChaCha20Poly1305(wrap_key)
       return {"kem_ct": kem_ct, "wrapped_dek": aead.encrypt(...)}
   ```

3. **Update models:**
   ```python
   wrap_scheme: str = "hybrid-x25519-mlkem768-hkdfsha256-xchacha20poly1305-v1"
   wrapped_dek_obj: dict  # {kem_ct_b64, wrap_blob_b64}
   ```

4. **Graceful degradation:**
   ```python
   def select_wrap_scheme(prefer="auto"):
       if prefer == "hybrid" and has_oqs():
           return WRAP_HYBRID
       elif prefer == "hpke" and has_hpke():
           return WRAP_HPKE
       else:
           return WRAP_LEGACY  # current implementation
   ```

**Status:** 🚧 Future work, ecosystem-dependent

---

## Upgrade Principles

1. **Never break old ledgers:** Scheme versioning ensures eternal verification
2. **Explicit over implicit:** All crypto choices documented in payloads
3. **Test before deploy:** Each upgrade requires new invariant tests
4. **Document threat model:** Explain *why* each upgrade matters

---

## Testing Requirements

For each new scheme:

```python
def test_new_scheme_round_trip():
    """Verify new scheme encrypts/decrypts correctly."""
    
def test_backward_compatibility():
    """Old schemes still verify after upgrade."""
    
def test_scheme_detection():
    """Correct scheme selected based on payload metadata."""
```

---

## Current Status Summary

| Feature | Status | Scheme Version |
|---------|--------|----------------|
| SHA-256 Merkle | ✅ Deployed | `sha256` |
| BLAKE3 Merkle | ✅ Deployed | `blake3` |
| ChaCha20-Poly1305 Vault | ✅ Deployed | `chacha20poly1305-v1` |
| X25519+HKDF+ChaCha20 Wrap | ✅ Deployed | `x25519-hkdf-chacha20poly1305-v1` |
| Ed25519 Signatures | ✅ Deployed | `ed25519-v1` |
| XChaCha20-Poly1305 Vault | 🕒 Pending library | `xchacha20poly1305-v1` |
| HPKE Wrap | 🕒 Pending library | `hpke-*-v1` |
| PQ-Hybrid Wrap | 🚧 Future | `hybrid-*-v1` |

---

## References

- [RFC 8439: ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- [RFC 9180: HPKE](https://www.rfc-editor.org/rfc/rfc9180)
- [NIST SP 800-208: ML-KEM](https://csrc.nist.gov/pubs/sp/800/208/final)
- [BLAKE3 Spec](https://github.com/BLAKE3-team/BLAKE3-specs)
- [Curve25519 (X25519/Ed25519)](https://cr.yp.to/ecdh.html)
