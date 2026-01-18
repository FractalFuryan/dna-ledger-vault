# Post-Quantum Cryptography Migration Roadmap

## Executive Summary

DNA Ledger Vault is preparing for **quantum-resistant cryptography** to protect genomic data against future quantum computer attacks. This roadmap outlines our transition to **NIST Post-Quantum Cryptography Standards** (FIPS 203, 204, 205).

**Timeline**: 2026-2027 (18-month gradual migration)  
**Strategy**: Hybrid classical+PQ → Full PQ  
**Impact**: Zero downtime, backward compatible

---

## Threat Model: Harvest Now, Decrypt Later

### The Quantum Threat

**Current Risk:**
- Quantum computers (Shor's algorithm) can break RSA, ECDSA, ECDH in polynomial time
- Adversaries are harvesting encrypted data TODAY for future decryption
- Genomic data has 50+ year sensitivity period

**Attack Scenario:**
```
2026: Adversary captures encrypted genomic data
      ↓
2030: 100-qubit error-corrected quantum computer available
      ↓
2035: Adversary decrypts all captured data using Shor's algorithm
      ↓
RESULT: 9 years of genomic data exposed
```

**DNA Ledger Vault Protection:**
- Hybrid mode TODAY: Defense-in-depth (classical + PQ)
- Full PQ by 2027: Quantum-resistant by default
- Forward secrecy: Key rotation limits exposure window

---

## NIST Post-Quantum Standards

### Selected Algorithms

DNA Ledger Vault will migrate to **NIST-approved PQ algorithms**:

#### 1. **ML-KEM** (Module-Lattice Key Encapsulation)
- **Standard**: FIPS 203
- **Use Case**: Key exchange (replaces X25519)
- **Variants**:
  - ML-KEM-768: 192-bit quantum security (MODERATE)
  - ML-KEM-1024: 256-bit quantum security (HIGH)
- **Security Basis**: Module Learning With Errors (MLWE)

#### 2. **ML-DSA** (Module-Lattice Digital Signature)
- **Standard**: FIPS 204
- **Use Case**: Digital signatures (replaces Ed25519)
- **Variants**:
  - ML-DSA-65: 192-bit quantum security (MODERATE)
  - ML-DSA-87: 256-bit quantum security (HIGH)
- **Security Basis**: Module Learning With Errors + FIAT-SHAMIR

#### 3. **SLH-DSA** (Stateless Hash-Based Signatures)
- **Standard**: FIPS 205
- **Use Case**: Backup signatures (conservative option)
- **Variants**:
  - SLH-DSA-128f: Fast variant
  - SLH-DSA-128s: Small variant
- **Security Basis**: Hash functions (very conservative)

### Why These Algorithms?

✅ **NIST Standardized**: Official US government approval  
✅ **Open Source**: Reference implementations available  
✅ **Patent-Free**: No licensing concerns  
✅ **Conservative Security**: Based on well-studied lattice problems  
✅ **Performance**: Practical for production use

---

## Migration Strategy

### Three-Phase Approach

```
Phase 1: CRYPTO AGILITY (Q1 2026) ✅ COMPLETE
├─ Implement algorithm abstraction layer
├─ Add scheme versioning to all crypto operations
├─ Create CryptoProvider protocol
└─ Test with current classical algorithms

Phase 2: HYBRID MODE (Q2-Q3 2026) ⏳ IN PROGRESS
├─ Deploy hybrid classical+PQ signatures
├─ Test with production workloads
├─ Monitor performance impact
└─ Gradual rollout to all users

Phase 3: FULL POST-QUANTUM (Q4 2026 - Q1 2027)
├─ Switch default to PQ-only mode
├─ Deprecate classical-only mode
├─ Complete key migration
└─ Quantum-resistant by default
```

---

## Technical Implementation

### Crypto Agility Framework

**Key Abstraction:**
```python
class CryptoProvider(Protocol):
    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes) -> bytes: ...
    def decrypt(self, key: bytes, ciphertext: bytes, aad: bytes) -> bytes: ...
    def sign(self, private_key: bytes, message: bytes) -> bytes: ...
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...
    def kem_keygen(self) -> tuple[bytes, bytes]: ...
    def kem_encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]: ...
    def kem_decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes: ...
```

**Three Providers:**
1. `ClassicalCryptoProvider`: Current Ed25519/X25519
2. `PostQuantumCryptoProvider`: ML-KEM/ML-DSA
3. `HybridCryptoProvider`: Both combined

### Hybrid Mode Design

**Signature Scheme:**
```
Hybrid-Ed25519-MLDSA65-v1:
  classical_sig = Ed25519.sign(message)
  pq_sig = ML-DSA-65.sign(message)
  final_sig = classical_sig || pq_sig
  
Verification: BOTH must verify (AND gate)
Security: Holds if EITHER classical OR PQ is secure
```

**KEM Scheme:**
```
Hybrid-X25519-MLKEM768-v1:
  ct_classical, ss_classical = X25519.encapsulate()
  ct_pq, ss_pq = ML-KEM-768.encapsulate()
  
  combined_ct = ct_classical || ct_pq
  combined_ss = KDF(ss_classical || ss_pq)
  
Security: Adversary must break BOTH to recover shared secret
```

---

## Key Size Impact

### Storage Requirements

| Algorithm | Current (Classical) | Post-Quantum | Increase |
|-----------|---------------------|--------------|----------|
| **Public Key** | 32 bytes (Ed25519) | 1,952 bytes (ML-DSA-65) | **61x** |
| **Signature** | 64 bytes | 3,309 bytes | **52x** |
| **KEM Public** | 32 bytes (X25519) | 1,184 bytes (ML-KEM-768) | **37x** |
| **KEM Ciphertext** | 32 bytes | 1,088 bytes | **34x** |

### Ledger Impact

**Example Dataset:**
- 1,000 events/year
- Current ledger size: 500 KB/year
- **PQ ledger size**: ~20 MB/year (40x increase)

**Mitigation:**
- Compression (PQ signatures compress well)
- Sparse storage (store keys separately)
- Archive old events after audit period

---

## Performance Considerations

### Benchmark Estimates

| Operation | Classical | Hybrid | Full PQ | Slowdown |
|-----------|-----------|--------|---------|----------|
| **Sign** | 0.05 ms | 0.3 ms | 0.5 ms | 10x |
| **Verify** | 0.1 ms | 0.4 ms | 0.6 ms | 6x |
| **KEM Encaps** | 0.05 ms | 0.2 ms | 0.3 ms | 6x |
| **KEM Decaps** | 0.05 ms | 0.2 ms | 0.3 ms | 6x |

**Impact Analysis:**
- ✅ Acceptable for genomic workflows (not latency-critical)
- ✅ Batch operations amortize overhead
- ⚠️  May require hardware acceleration for high-throughput scenarios

---

## Migration Tasks

### Phase 2: Hybrid Mode (Q2-Q3 2026)

#### 2.1 Install Dependencies
```bash
# Install liboqs (Open Quantum Safe library)
pip install liboqs-python

# Or build from source for production
git clone https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python && pip install .
```

#### 2.2 Enable Hybrid Configuration
```python
from vault.pq_crypto import CryptoConfig, get_crypto_provider

# Update default config
config = CryptoConfig.hybrid_transition()
provider = get_crypto_provider(config)

# Use in ledger operations
signature = provider.sign(private_key, message)
```

#### 2.3 Migrate Identity Keys
```bash
# Generate hybrid keypairs for existing identities
dna-ledger migrate-keys --mode hybrid --out state/

# Test signature compatibility
dna-ledger test-hybrid-sigs --out state/
```

#### 2.4 Update Wrapped Keys
```bash
# Re-wrap DEKs with ML-KEM-768
dna-ledger rewrap-keys --kem ml-kem-768 --out state/
```

#### 2.5 Monitor Performance
```bash
# Benchmark hybrid operations
dna-ledger benchmark --mode hybrid

# Expected results:
# Sign: ~0.3ms (acceptable)
# Verify: ~0.4ms (acceptable)
# Ledger append: ~1ms (acceptable)
```

### Phase 3: Full PQ (Q4 2026)

#### 3.1 Switch Default Config
```python
# Update production config
config = CryptoConfig.post_quantum()
config.strict_pq_only = True
```

#### 3.2 Deprecation Timeline
```
2026-10: Announce classical deprecation
2026-11: Warning messages for classical-only keys
2026-12: Reject new classical keys
2027-01: PQ-only mode enforced
```

---

## Security Analysis

### Quantum Security Levels

DNA Ledger Vault targets **NIST Security Level 3** (AES-192 equivalent):

| Algorithm | Classical Security | Quantum Security | NIST Level |
|-----------|-------------------|------------------|------------|
| ML-KEM-768 | 256-bit | **192-bit** | 3 |
| ML-DSA-65 | 256-bit | **192-bit** | 3 |
| SLH-DSA-128f | 256-bit | **128-bit** | 1 |

**Rationale:**
- Level 3 = 192-bit quantum security
- Protects against 100+ qubit quantum computers
- Conservative estimate: Safe until 2040+

### Attack Resistance

✅ **Shor's Algorithm**: Ineffective (lattice problems are hard)  
✅ **Grover's Algorithm**: Mitigated by larger key sizes  
✅ **Harvest Now, Decrypt Later**: Defeated by hybrid mode TODAY  
✅ **Side-Channel Attacks**: Constant-time implementations  

---

## Testing Strategy

### Test Coverage

```python
# tests/test_pq_crypto.py

def test_hybrid_signature_round_trip():
    """Test hybrid Ed25519+ML-DSA-65 signatures."""
    provider = HybridCryptoProvider()
    keypair = provider.generate_signing_keypair()
    
    message = b"genomic data hash"
    signature = provider.sign(keypair.private, message)
    
    assert provider.verify(keypair.public, message, signature)

def test_hybrid_kem_round_trip():
    """Test hybrid X25519+ML-KEM-768 encapsulation."""
    provider = HybridCryptoProvider()
    pub, priv = provider.kem_keygen()
    
    ct, ss_sender = provider.kem_encapsulate(pub)
    ss_receiver = provider.kem_decapsulate(priv, ct)
    
    assert ss_sender == ss_receiver

def test_backward_compatibility():
    """Ensure PQ provider can verify classical signatures."""
    classical = ClassicalCryptoProvider()
    hybrid = HybridCryptoProvider()
    
    # Classical signature
    message = b"test"
    sig = classical.sign(classical_key, message)
    
    # Hybrid should verify (backward compat)
    assert hybrid.verify(classical_key, message, sig)
```

---

## Compatibility Matrix

### Ledger Compatibility

| Writer Config | Reader Config | Compatible? |
|---------------|---------------|-------------|
| Classical | Classical | ✅ Yes |
| Classical | Hybrid | ✅ Yes (backward compat) |
| Classical | PQ-Only | ⚠️ No (strict mode) |
| Hybrid | Classical | ✅ Yes (classical component) |
| Hybrid | Hybrid | ✅ Yes |
| Hybrid | PQ-Only | ⚠️ Partial (PQ component only) |
| PQ-Only | Classical | ❌ No |
| PQ-Only | Hybrid | ✅ Yes |
| PQ-Only | PQ-Only | ✅ Yes |

**Migration Path:**
```
Classical → Hybrid (read-write) → PQ-Only (write-only classical deprecated)
```

---

## Operational Considerations

### Monitoring

**Key Metrics:**
- Signature generation time (p50, p99)
- Signature verification time
- Ledger append latency
- Storage growth rate
- Error rate (signature failures)

**Alerts:**
```
WARN: Signature time > 1ms (hybrid should be ~0.3ms)
ERROR: Verification failure rate > 0.1%
INFO: Ledger storage growth > 50 MB/month
```

### Disaster Recovery

**Backup Strategy:**
- Store PQ keys in HSM (Hardware Security Module)
- Offline backup of hybrid keypairs
- Test key recovery quarterly
- Document PQ key import/export procedures

**Key Rotation:**
- Rotate ML-DSA signing keys annually
- Rotate ML-KEM wrapping keys per dataset
- Archive old keys for historical verification

---

## Dependencies

### Required Packages

```bash
# Python packages
pip install liboqs-python>=0.8.0  # PQ algorithms
pip install cryptography>=41.0.0  # Classical crypto

# System libraries (Linux)
apt-get install liboqs-dev

# System libraries (macOS)
brew install liboqs
```

### Optional Packages

```bash
# Hardware acceleration
pip install intel-ipp-crypto  # Intel IPP for faster lattice ops

# Benchmarking
pip install pyperf
```

---

## Future Enhancements

### 2027-2028 Roadmap

1. **Hardware Acceleration**
   - Integrate Intel QAT (QuickAssist Technology)
   - GPU acceleration for ML-KEM operations
   - FPGA implementations for ultra-low latency

2. **Advanced Features**
   - Zero-knowledge proofs with PQ signatures
   - Threshold ML-DSA signatures (multi-party)
   - Quantum-resistant homomorphic encryption

3. **Standardization**
   - ISO/IEC 14888-4 (PQ signatures)
   - NIST SP 800-208 (KEM recommendations)
   - FIPS 140-3 certification for PQ modules

---

## References

1. **NIST PQ Standards**:
   - [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
   - [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
   - [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)

2. **Open Quantum Safe**:
   - [liboqs Library](https://github.com/open-quantum-safe/liboqs)
   - [liboqs-python](https://github.com/open-quantum-safe/liboqs-python)

3. **Research Papers**:
   - "CRYSTALS-Kyber" (ML-KEM basis)
   - "CRYSTALS-Dilithium" (ML-DSA basis)
   - "SPHINCS+" (SLH-DSA basis)

4. **Industry Guidance**:
   - NIST SP 800-208: Recommendation for KEM
   - NSA CNSA 2.0: Commercial National Security Algorithm Suite
   - ETSI Quantum-Safe Cryptography

---

## Support & Questions

**Technical Contact**: cryptography-team@dna-ledger-vault.example  
**Migration Support**: See [CRYPTO_UPGRADES.md](CRYPTO_UPGRADES.md)  
**Security Concerns**: [SECURITY.md](SECURITY.md)

**Disclaimer**: This roadmap is subject to change based on NIST guidance, security research, and operational experience. Always consult with cryptographic experts before deploying PQ algorithms in production.
