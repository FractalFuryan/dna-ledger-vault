# Glossary

⭕️🛑 **DNA Ledger Vault — Technical Terminology**

---

## Cryptographic Terms

### AEAD (Authenticated Encryption with Associated Data)
Encryption primitive that provides both confidentiality and authenticity. DNA Ledger uses ChaCha20-Poly1305.

### DEK (Data Encryption Key)
Per-dataset encryption key (256-bit). Rotated for forward secrecy, wrapped to authorized grantees via X25519 ECDH.

### Domain Separation
Cryptographic practice of prefixing hash inputs with context tags to prevent structural collision attacks. Example: `H_LEAF(chunk)` vs `H_NODE(left, right)`.

### Ed25519
Elliptic curve signature algorithm. Deterministic, collision-resistant, 256-bit security level. Used for ledger event signing.

### Forward Secrecy
Property where compromise of current keys does not reveal past encrypted data. Achieved via key rotation + destruction of old DEKs.

### HKDF (HMAC-based Key Derivation Function)
Cryptographic key derivation using SHA-256. Used in X25519 ECDH wrapping to derive encryption keys from shared secrets.

### Merkle Tree
Binary hash tree enabling tamper-evident chunk verification. Leaf nodes hash data chunks; internal nodes hash child pairs.

### Nonce (Number Used Once)
Random value ensuring unique ciphertext even with identical plaintext. DNA Ledger uses 96-bit nonces (safe with key-per-dataset isolation).

### Post-Compromise Safety
Property where key rotation invalidates compromised wrappings. Revoked users excluded from re-wrapping.

### X25519
Elliptic curve Diffie-Hellman key agreement. Used to wrap DEKs to grantee public keys.

---

## Ledger Terms

### Append-Only Ledger
Immutable log where entries are only added, never modified or deleted. State changes emit new events (grants, revocations, rotations).

### Block Hash Chain
Each ledger block references parent block hash, forming tamper-evident chain. Modification of any block invalidates all subsequent blocks.

### Canonical JSON
Deterministic JSON serialization (sorted keys, no whitespace) ensuring identical hash for equivalent objects.

### Consent Grant
Explicit permission event authorizing specific grantee to access dataset for defined purpose and time period.

### Consent Revocation
Explicit event revoking a previous grant. Revoked grants cannot be used for compute attestation.

### Compute Attestation
Ledger event recording algorithm execution on dataset. Requires active, unrevoked consent grant.

### Hash Chain Integrity
Property where tampering with any block breaks cryptographic linkage to subsequent blocks.

### Key Rotation Event
Ledger event recording DEK rotation. Triggers re-encryption of vault + re-wrapping to active grantees only.

### Payload Hash
Domain-separated hash of ledger event payload. Used as input to signature generation.

---

## Ethics & Architecture Terms

### Ethics Anchor
Cryptographic hash (`SHA-256: 65b14d584f5a5fd070fe985eeb86e14cb3ce56a4fc41fd9e987f2259fe1f15c1`) of hard ethical invariants, verified across docs/tests/CI.

### Likeness Personalization (PROHIBITED)
Steering outputs toward a specific person's body/face/identity. Examples:
- "Make it like me"
- "Make it like [specific person]"
- Learning from prior outputs to converge on recognizable identity
- Iterative resampling to approach target identity

**Status:** Architecturally prohibited, violates ethics anchor.

### Probabilistic Distance Doctrine
> The system permits incidental human-like interpretations arising from random sampling, while enforcing sufficient probabilistic and structural distance to prevent convergence toward real human bodies or individuals.

Ensures outputs are probabilistically and structurally different from any real person.

### Procedural Personalization (ALLOWED)
Parameterized variation that does **not** target any real individual. Examples:
- Palette customization
- Abstract style preferences
- Geometric motifs
- Non-identifying shape grammars

**Key distinction:** Parameters control aesthetic variation, never identity convergence.

---

## Zero-Knowledge Terms

### Field-Valid Operations
Arithmetic operations permitted within ZK circuit constraints. Excludes: floats, `abs`, `floor`, `sqrt`, real arithmetic.

### Halo2
Zero-knowledge proof system using polynomial commitments. Used for teleport chain verification (Option A spec).

### Lookup Table
Precomputed table enabling non-arithmetic operations (XOR, scaling) in ZK circuits.

### Selector Bit
Boolean constraint variable (`b ∈ {0,1}`) choosing between circuit branches. Proves branch taken, not randomness.

### Teleport Chain
Multi-step state evolution with nonlocal jumps. ZK proof verifies correctness without revealing intermediate states.

---

## State Mixer Terms

### Ancilla Chain
Deterministic auxiliary entropy source derived from `(seed, step_index)`. Used for routing decisions, not learning.

### Dual Drift
Two independent mixing functions (`J(k)`, `Jb(k)`) reducing structural predictability under single-function attacks.

### Enhanced F_k
> Nonlinear modular state mixer with entropy-gated nonlocal jumps (hybrid chaotic mixer)

Classification: deterministic chaos with optional CSPRNG salt for routing.

### GeoPhase A
Seed → render-driving parameter vector projection. Directly controls output generation.

### GeoPhase B
Seed → audit-only vector projection (orthogonal to Phase A). Used for non-collapse measurement only.

### Stateless Teleport Proxy
Deterministic jump probability function `p_tp_state(k, Ja, Jb)` with no history dependence. Avoids learning loops.

---

## Scheme Versioning Terms

### AEAD Scheme
`chacha20poly1305-v1` — Current authenticated encryption scheme. Future: `xchacha20poly1305-v1`.

### Hash Scheme
`sha256-v1` — Canonical hashing. Supplemental: `blake3-v1` (10x faster).

### Wrap Scheme
`x25519-hkdf-chacha20poly1305-v1` — Current DEK wrapping scheme. Future: `hpke-v1`, `x25519-mlkem768-v1` (post-quantum).

---

## Cross-References

- **Ethics:** [ETHICS-PROBABILISTIC-DISTANCE.md](ETHICS-PROBABILISTIC-DISTANCE.md)
- **Security:** [SECURITY.md](SECURITY.md)
- **Architecture:** [THREAD-2026-01-15.md](THREAD-2026-01-15.md)
- **Crypto Upgrades:** [CRYPTO_UPGRADES.md](CRYPTO_UPGRADES.md)
