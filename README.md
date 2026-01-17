# dna-ledger-vault 🧬⛓️🔐

[![Release](https://img.shields.io/badge/release-v1.0.0--audit-blue.svg)](https://github.com/FractalFuryan/dna-ledger-vault/releases/tag/v1.0.0-audit)
[![Tests](https://img.shields.io/badge/tests-12%2F12-brightgreen.svg)](#security-invariants)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**DNA stays off-chain (encrypted).** A hash-chained, signed ledger stores only:
- Dataset fingerprints (SHA-256 + BLAKE3 dual hashing, Merkle roots)
- Consent grants (purpose-scoped, time-limited)
- Revocations (explicit on-ledger truth)
- Compute attestations (algo + output hashing)
- Key rotation events (forward secrecy + post-compromise safety)

This is the "only kind" of DNA blockchain tech that doesn't blow up privacy:
✅ Zero raw DNA on-chain/ledger  
✅ Cryptographic provenance on every entry  
✅ Consent enforced before compute is recorded  
✅ **Audit-grade cryptography** with scheme versioning  
✅ **Frozen dependencies** for reproducible audits  

---

## 🔒 Security Status (v1.0.0-audit)

**Cryptographic Primitives:**
- **AEAD**: ChaCha20-Poly1305 (96-bit nonces, safe with key-per-dataset isolation)
- **Key Wrapping**: X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305
- **Signatures**: Ed25519 (deterministic, collision-resistant)
- **Hashing**: SHA-256 (canonical) + BLAKE3 (supplemental, 10x faster)
- **Scheme Versioning**: All crypto operations tagged for forward-compatible upgrades

**Security Invariants:** 14 verified properties (see [SECURITY.md](docs/SECURITY.md))  
**Test Coverage:** 12/12 tests passing (6 invariants + 6 crypto schemes)  
**Dependencies:** Locked to exact versions in `requirements-lock.txt`

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for complete audit compliance summary.

---

## Threat model (non-negotiable)
DNA is inherently identifying. This repo **never** stores raw sequences/variants in the ledger.
Only tamper-evident proofs and permissions are recorded.

**Trust Model:**
- Ledger integrity depends on cryptographic verification (hash chain + Ed25519 signatures)
- Confidentiality depends on vault encryption (ChaCha20-Poly1305) + key wrapping (X25519)
- Access control enforced via policy engine (consent grants + revocations)
- Forward secrecy via key rotation (old DEKs destroyed after re-encryption)

---

## What's implemented (v1.0.0-audit)

### 🔏 Cryptographic Provenance (Ed25519)
Every ledger payload is **signed by its creator** with deterministic Ed25519 signatures.  
Ledger verification checks:
- Hash-chain integrity (each block references parent hash)
- Signature validity on every event
- No hash collisions across 14 security invariants

### 🧾 Consent + Revocation (Policy Engine)
- **Consent grants**: purpose-scoped + time-limited + binding AAD
- **Revocations**: explicit on-ledger events (no ambiguity)
- **Compute attestations**: require valid, unrevoked grant (enforced pre-execution)
- **Policy**: consent must exist, be non-expired, and non-revoked

### 🗝️ Real Access Control (X25519 ECDH Wrapping)
- DNA dataset encrypted in vault with per-dataset **DEK** (256-bit, ChaCha20-Poly1305)
- DEK **wrapped** to grantee public keys via X25519 ECDH + HKDF-SHA256
- Only grantee can unwrap (no shared secrets, cryptographically isolated)
- **Scheme versioning**: `x25519-hkdf-chacha20poly1305-v1` for forward compatibility

### 🔁 Key Rotation (Forward Secrecy)
- Rotate DEKs (re-encrypt entire vault with new key)
- Automatically re-wrap **only to active grantees** (revoked users excluded)
- Old DEKs destroyed (forward secrecy guarantee)
- Post-compromise safety: rotation invalidates all previous wrappings

### 🌲 Merkle Proofs (Chunk Verification)
- Datasets chunked with SHA-256 + BLAKE3 dual hashing
- Merkle tree construction for tamper-evident chunk proofs
- Inclusion proof generation + verification (audit-grade, 6/6 tests passing)
- Supports selective disclosure (prove chunk without revealing full dataset)

### 🔐 Scheme Versioning (Future-Proof Crypto)
All cryptographic operations tagged with scheme identifiers:
- `wrap_scheme`: Key wrapping algorithm version
- `hash_scheme`: Hashing algorithm version  
- `aead_scheme`: AEAD cipher version

---

## ⛓️ Ethereum Bridge (v0.1)

⭕️🛑 **Privacy-safe on-chain attestation** for GeoPhase commitments.

- **Contracts**: [AnankeAttestationRegistry](contracts/AnankeAttestationRegistry.sol), [AnankeRevocationRegistry](contracts/AnankeRevocationRegistry.sol)
- **Target**: Base L2 (low gas, fast finality)
- **Storage**: Commitments only - no media, no likeness, no user data
- **Features**: One-shot attestation, public revocation, ethics anchor verification

**Quick Start:**
```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Build contracts
make contracts

# Deploy to Base Sepolia (testnet)
cp .env.example .env  # Fill in PRIVATE_KEY
python -m geophase_eth.deploy --network base-sepolia

# Run example workflow
python -m geophase_eth.example
```

See [docs/GEO-COMMIT-SPEC.md](docs/GEO-COMMIT-SPEC.md) for commitment format and [docs/DEPLOYMENT-ETH.md](docs/DEPLOYMENT-ETH.md) for deployment guide.

Enables seamless upgrades (XChaCha20, HPKE, PQ-hybrid) without breaking old ledgers.  
See [CRYPTO_UPGRADES.md](docs/CRYPTO_UPGRADES.md) for upgrade roadmap.

---

## Repo layout
- `vault/` — Off-chain encryption (ChaCha20-Poly1305), vault storage, DEK wrapping (X25519)
- `dna_ledger/` — Hashing (SHA-256 + BLAKE3), Pydantic models, signed hash-chained ledger
- `cli/` — Command-line workflow (dataset commit, consent, rotation, verification)
- `tests/` — 12 tests: 6 security invariants + 6 crypto scheme tests
- `docs/` — Security invariants, upgrade roadmap, release notes

---

## Install (Reproducible Audit Build)

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Option 1: Locked dependencies (audit-grade, exact versions)
pip install -r requirements-lock.txt

# Option 2: Bounded dependencies (development, allows patches)
pip install -r requirements.txt

# Option 3: Install with Ethereum bridge support
pip install -r requirements.txt
```

**For Ethereum bridge development:**
```bash
make install-foundry  # Install Foundry (Solidity toolchain)
make contracts        # Build smart contracts
```

**Verify installation:**
```bash
pytest -v                    # 12/12 tests should pass
ruff check .                 # Zero lint violations
mypy .                       # Zero type errors
```

---

## Security Invariants

Run test suite to verify all 14 security properties:

```bash
pytest tests/test_invariants.py -v
pytest tests/test_crypto_schemes.py -v
```

**Verified Properties:**
1. ✅ **Chain integrity**: No hash collisions, valid parent references
2. ✅ **Signature validity**: All Ed25519 signatures verify correctly  
3. ✅ **Consent enforcement**: No attestations without grants
4. ✅ **Revocation blocks access**: Revoked grants cannot authorize compute
5. ✅ **Merkle proofs**: Valid inclusion proofs for all dataset chunks
6. ✅ **Nonce uniqueness**: ChaCha20-Poly1305 nonces never repeat (100-iteration proof)
7. ✅ **AAD binding**: Cross-dataset ciphertext tampering detected
8. ✅ **Scheme versioning**: All models have crypto scheme fields
9. ✅ **Key isolation**: One key per dataset (no key reuse)
10. ✅ **Forward secrecy**: Rotation invalidates old wrappings
11. ✅ **BLAKE3 consistency**: Dual hashing produces deterministic outputs
12. ✅ **Deterministic signatures**: Ed25519 signs identically for same input

See [SECURITY.md](docs/SECURITY.md) for complete security documentation.

---

## Quick demo (end-to-end)

### 1) Create identities (owner + researchers)

```bash
python -m cli.main init-identities --out state --who dave
python -m cli.main init-identities --out state --who researcher1
python -m cli.main init-identities --out state --who researcher2
python -m cli.main init-identities --out state --who hacker
```

### 2) Commit dataset (signed + encrypted off-chain)

```bash
python -m cli.main commit --dataset samples/sample.vcf --out state --owner dave
# prints dataset_id: ds_....
```

### 3) Grant consent (signed) + wrap DEK to grantee

```bash
python -m cli.main grant --out state --actor dave --dataset-id ds_... --grantee researcher1 --purpose research --days 30
python -m cli.main grant --out state --actor dave --dataset-id ds_... --grantee researcher2 --purpose research --days 30
```

### 4) Attest compute (enforced: must have active, unrevoked grant)

```bash
python -m cli.main attest --out state --actor researcher1 --dataset-id ds_... --purpose research --algo "GWAS-v1" --result samples/result.json
python -m cli.main attest --out state --actor researcher2 --dataset-id ds_... --purpose research --algo "GWAS-v1" --result samples/result.json

# Unauthorized actor is blocked:
python -m cli.main attest --out state --actor hacker --dataset-id ds_... --purpose research --algo "GWAS-v1" --result samples/result.json
# -> ❌ No active, unrevoked consent grant found.
```

### 5) Revoke consent (explicit on-ledger)

```bash
python -m cli.main revoke-consent --out state --actor dave --dataset-id ds_... --grant-id cg_... --reason "revoked by owner"
```

After revocation:

```bash
python -m cli.main attest --out state --actor researcher1 --dataset-id ds_... --purpose research --algo "GWAS-v1" --result samples/result.json
# -> ❌ blocked
```

### 6) Rotate key (forward secrecy + re-wrap to active grantees only)

```bash
python -m cli.main rotate-key --out state --actor dave --dataset-id ds_...
```

Now only active researchers continue. Revoked users don't get the new DEK.

### 7) Verify ledger (chain + signatures)

```bash
python -m cli.main verify --out state
# -> ✅ Ledger verify
```

---

## Commands Reference

* **`init-identities`** — Generate Ed25519 + X25519 keypairs for an identity
* **`commit`** — Commit dataset (dual hashing + Merkle root), encrypt to vault, signed entry
* **`grant`** — Record consent grant, wrap DEK to grantee, signed entry with scheme versioning
* **`revoke-consent`** — Explicit revocation event, signed entry
* **`attest`** — Record compute attestation (requires active, unrevoked consent), signed entry
* **`rotate-key`** — Rotate DEK, re-encrypt vault, re-wrap to active grantees, signed rotation event
* **`verify`** — Verify hash chain + signatures + Merkle proofs

---

## Development

### Run Tests
```bash
pytest -v                              # All tests
pytest tests/test_invariants.py -v     # Security invariants (6 tests)
pytest tests/test_crypto_schemes.py -v # Crypto schemes (6 tests)
```

### Static Analysis
```bash
ruff check .                           # Lint (zero violations)
ruff format .                          # Format code
mypy .                                 # Type check (zero errors)
```

### CI/CD
GitHub Actions workflow runs on push:
- Matrix testing (Python 3.12)
- Package installation verification
- Full test suite (12/12 passing)
- SECURITY.md invariant verification

---

## Roadmap

### v1.0.0-audit (Current) ✅
- ChaCha20-Poly1305 AEAD (96-bit nonces, key-per-dataset isolation)
- X25519 ECDH + HKDF-SHA256 key wrapping
- Ed25519 signatures (deterministic, collision-resistant)
- SHA-256 + BLAKE3 dual hashing
- Scheme versioning for all crypto operations
- Merkle proof generation + verification
- 14 security invariants verified
- Frozen dependencies for audit reproducibility

### v1.1.0 (Future Upgrades) 🚀
- **XChaCha20-Poly1305**: 192-bit nonces (when cryptography library supports)
- **HPKE wrapping**: RFC 9180 hybrid public key encryption
- **PQ-hybrid**: X25519 + ML-KEM-768 post-quantum resistance

See [CRYPTO_UPGRADES.md](docs/CRYPTO_UPGRADES.md) for complete upgrade strategy.

---

## Next tiers (optional)

* **Merkle extensions**: Zero-knowledge proofs for SNP buckets (prove marker without revealing genome)
* **Chain integration**: Ethereum/Solana contracts + on-chain attestation anchoring
* **Multi-party compute**: Secure enclaves (SGX/SEV) + remote attestation
* **Differential privacy**: ε-DP noise injection for aggregate genomic queries

---

## Documentation

- [SECURITY.md](docs/SECURITY.md) — Security model, cryptographic primitives, 14 invariants, ethics anchor
- [CRYPTO_UPGRADES.md](docs/CRYPTO_UPGRADES.md) — Future crypto upgrade roadmap (XChaCha, HPKE, PQ)
- [GLOSSARY.md](docs/GLOSSARY.md) — Technical terminology, ethics concepts, cryptographic terms
- [RELEASE_NOTES.md](RELEASE_NOTES.md) — v1.0.0-audit release summary
- [requirements-lock.txt](requirements-lock.txt) — Frozen dependency snapshot for audits

### Technical Specifications (2026-01-15)
- [THREAD-2026-01-15.md](docs/THREAD-2026-01-15.md) — Thread compilation: ethics doctrine, architecture notes
- [ETHICS-PROBABILISTIC-DISTANCE.md](docs/ETHICS-PROBABILISTIC-DISTANCE.md) — Probabilistic distance doctrine
- [STATE-MIXER-FK.md](docs/STATE-MIXER-FK.md) — Nonlinear state mixer (formal spec, v2 strengthening)
- [ZK-TELEPORT-OPTION-A.md](docs/ZK-TELEPORT-OPTION-A.md) — Halo2 teleport proof (field-valid, rigorous)
- [GEO-PHASE.md](docs/GEO-PHASE.md) — Dual geo-phase architecture (audit-only cosine buffer)

### Ethereum Bridge (2026-01-17)
- [GEO-COMMIT-SPEC.md](docs/GEO-COMMIT-SPEC.md) — On-chain commitment format & verification flow
- [DEPLOYMENT-ETH.md](docs/DEPLOYMENT-ETH.md) — Base L2 deployment guide
- [THREAT-MODEL-ETH.md](docs/THREAT-MODEL-ETH.md) — Security analysis for on-chain layer

### Development Tools
- **Makefile**: `make status`, `make docs-verify`, `make test`, `make lint`
- **Export Evidence**: `python -m cli.main export-evidence` — Generate audit bundles

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Citation

If you use this work in academic research, please cite:

```bibtex
@software{dna_ledger_vault_2026,
  author = {FractalFuryan},
  title = {dna-ledger-vault: Audit-Grade Genomic Data Ledger},
  year = {2026},
  version = {1.0.0-audit},
  url = {https://github.com/FractalFuryan/dna-ledger-vault}
}
```

---

## Recent Updates (2026-01-15)

**Ethics & Documentation:**
- Added ethics anchor verification (SHA-256: `65b14d584...`)
- Comprehensive technical glossary with 40+ terms
- Formal mathematical specifications for state mixer and ZK proofs

**Code Implementations:**
- Evidence export command for audit bundle generation
- Documentation verification scripts
- Makefile with convenient build targets

**All updates maintain audit-grade posture with zero breaking changes.**

---

## Thread Archive

- [docs/THREAD-2026-01-15.md](docs/THREAD-2026-01-15.md) — January 15, 2026 compilation (ethics doctrine, geo-phase audit, state mixer notes, Halo2 Option A planning)
