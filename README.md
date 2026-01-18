# dna-ledger-vault 🧬⛓️🔐

[![Release](https://img.shields.io/badge/release-v1.1.0--ethereum-blue.svg)](https://github.com/FractalFuryan/dna-ledger-vault)
[![Tests](https://img.shields.io/badge/tests-55%2F55-brightgreen.svg)](#security-invariants)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Boundary](https://img.shields.io/badge/boundary-enforced-green.svg)](#-math-vs-interpretation-boundary)

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
**Test Coverage:** 55/55 tests passing (30 core + 25 RFC6979 + Ethereum integration)  
**Dependencies:** Locked to exact versions in `requirements-lock.txt`  
**Ethereum Bridge:** v0.1.1 production-hardened (Base L2, fail-closed, bytecode lock)  
**Signing:** RFC6979 deterministic ECDSA (secp256k1, low-S normalized)  
**Boundary Enforcement:** CI-gated math/interpretation separation

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for complete audit compliance summary.

---

## 🔬 Math vs Interpretation Boundary

**We use the classical Gaussian explicit formula as a fixed mathematical substrate.** No new number-theoretic claims are made.

Our contribution is an **optional interpretive/constraint layer** that does not modify the underlying mathematics. This separation ensures:

- ✅ Mathematical substrate remains **classical, unchanged, non-owned**
- ✅ Interpretive frameworks are **optional, falsifiable, clearly labeled**
- ✅ Engineering systems are **independent** of speculative claims
- ✅ Cryptographic guarantees are **verifiable** without belief in upper layers

**Documentation:**
- [docs/SCALAR_WAZE_BOUNDARY.md](docs/SCALAR_WAZE_BOUNDARY.md) - Math/interpretation separation
- [docs/NON_CLAIMS.md](docs/NON_CLAIMS.md) - Hard boundary (what we do NOT claim)
- [docs/CLAIMS_REGISTER.md](docs/CLAIMS_REGISTER.md) - Explicit categorization of all claims

**Enforcement:** `make boundary` verifies this boundary via CI gate.

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

## ⛓️ Ethereum Bridge (v0.1.1 Production-Hardened)

⭕️🛑 **Privacy-safe on-chain attestation** for GeoPhase commitments.

**Core Features:**
- **Contracts**: [AnankeAttestationRegistry](contracts/src/AnankeAttestationRegistry.sol), [AnankeRevocationRegistry](contracts/src/AnankeRevocationRegistry.sol)
- **Target**: Base L2 (low gas ~$0.01-0.10/tx, 2-second finality)
- **Storage**: Commitments only - no media, no likeness, no user data
- **Signing**: RFC6979 deterministic ECDSA (secp256k1, low-S normalized)

**Production Hardening (v0.1.1):**
- ✅ **Fail-closed server**: STRICT_CHAIN + STRICT_REVOCATION defaults
- ✅ **Bytecode lock**: Contract integrity verification at startup
- ✅ **Canonical commitments**: PREFIX_V1 domain separation
- ✅ **Health monitoring**: RPC latency tracking, error rates
- ✅ **FastAPI middleware**: Pre-generation gate enforcement
- ✅ **Comprehensive tests**: 18/18 passing (geocommit + fail-closed + bytecode lock)

**Quick Start:**
```bash
# Install dependencies
make install
pip install web3 eth-account python-dotenv ecdsa  # Ethereum deps

# Install Foundry (Solidity toolchain)
make install-foundry

# Build contracts
make contracts

# Configure environment
cp .env.example .env  # Fill in RPC URLs, contract addresses, etc.

# Verify boundary enforcement
make boundary  # Ensures math/interpretation separation

# Run comprehensive tests
pytest -v  # 55/55 tests (includes Ethereum integration)

# Deploy to Base Sepolia (testnet)
python -m geophase_eth.deploy --network base-sepolia

# Run RFC6979 signing example
python examples/geophase_signing_example.py
```

**Documentation:**
- [docs/GEO-COMMIT-SPEC.md](docs/GEO-COMMIT-SPEC.md) - Commitment format specification
- [docs/DEPLOYMENT-ETH.md](docs/DEPLOYMENT-ETH.md) - Deployment guide
- [docs/REGULATOR-SUMMARY.md](docs/REGULATOR-SUMMARY.md) - Compliance documentation
- [docs/RFC6979-NONCE-POLICY.md](docs/RFC6979-NONCE-POLICY.md) - Signing policy
- [ETHEREUM-BRIDGE-SUMMARY.md](ETHEREUM-BRIDGE-SUMMARY.md) - Architecture overview

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

### v1.1.0-ethereum (Current) ✅
- **Base L2 Integration**: Privacy-safe on-chain attestations (commitments only)
- **Production Hardening**: Fail-closed server, bytecode lock, health monitoring
- **RFC6979 Signing**: Deterministic ECDSA (secp256k1, low-S normalized)
- **Boundary Enforcement**: CI-gated math/interpretation separation
- ChaCha20-Poly1305 AEAD (96-bit nonces, key-per-dataset isolation)
- X25519 ECDH + HKDF-SHA256 key wrapping
- Ed25519 signatures (internal identities, deterministic)
- SHA-256 + BLAKE3 dual hashing
- Scheme versioning for all crypto operations
- Merkle proof generation + verification
- **55/55 tests passing** (30 core + 25 RFC6979 + Ethereum)
- Frozen dependencies for audit reproducibility

### v1.0.0-audit (2026-01-15) ✅
- Initial audit-grade release
- 14 security invariants verified
- 12/12 core tests passing
- Comprehensive documentation

### v1.2.0 (Future Upgrades) 🚀
- **XChaCha20-Poly1305**: 192-bit nonces (when cryptography library supports)
- **HPKE wrapping**: RFC 9180 hybrid public key encryption
- **PQ-hybrid**: X25519 + ML-KEM-768 post-quantum resistance
- **Ethereum v0.2**: Signature-gated revocation, NFT layer (seed-rights), batch attestation
- **Event indexer**: CSV export for audits, /health/eth endpoint

See [CRYPTO_UPGRADES.md](docs/CRYPTO_UPGRADES.md) and [docs/V0_2_DESIGN_NOTES.md](docs/V0_2_DESIGN_NOTES.md) for complete upgrade strategy.

---

## Next tiers (optional)

* **Merkle extensions**: Zero-knowledge proofs for SNP buckets (prove marker without revealing genome)
* **Chain integration**: Ethereum/Solana contracts + on-chain attestation anchoring
* **Multi-party compute**: Secure enclaves (SGX/SEV) + remote attestation
* **Differential privacy**: ε-DP noise injection for aggregate genomic queries

---

## Documentation

### Core Documentation
- [SECURITY.md](docs/SECURITY.md) — Security model, cryptographic primitives, 14 invariants, ethics anchor
- [CRYPTO_UPGRADES.md](docs/CRYPTO_UPGRADES.md) — Future crypto upgrade roadmap (XChaCha, HPKE, PQ)
- [GLOSSARY.md](docs/GLOSSARY.md) — Technical terminology, ethics concepts, cryptographic terms
- [RELEASE_NOTES.md](RELEASE_NOTES.md) — Release summaries
- [requirements-lock.txt](requirements-lock.txt) — Frozen dependency snapshot for audits

### Ethereum Bridge (v0.1.1)
- [ETHEREUM-BRIDGE-SUMMARY.md](ETHEREUM-BRIDGE-SUMMARY.md) — Architecture overview
- [docs/REGULATOR-SUMMARY.md](docs/REGULATOR-SUMMARY.md) — Compliance documentation (400+ lines)
- [docs/WHAT-THIS-IS-NOT.md](docs/WHAT-THIS-IS-NOT.md) — Clear boundary definitions
- [docs/V0_2_DESIGN_NOTES.md](docs/V0_2_DESIGN_NOTES.md) — Future roadmap
- [docs/GEO-COMMIT-SPEC.md](docs/GEO-COMMIT-SPEC.md) — On-chain commitment format
- [docs/DEPLOYMENT-ETH.md](docs/DEPLOYMENT-ETH.md) — Base L2 deployment guide
- [docs/THREAT-MODEL-ETH.md](docs/THREAT-MODEL-ETH.md) — Security analysis

### RFC6979 Deterministic ECDSA
- [docs/RFC6979-NONCE-POLICY.md](docs/RFC6979-NONCE-POLICY.md) — Nonce generation policy
- [docs/RFC6979-IMPLEMENTATION.md](docs/RFC6979-IMPLEMENTATION.md) — Technical summary
- [examples/geophase_signing_example.py](examples/geophase_signing_example.py) — Working demo

### Boundary Enforcement
- [docs/SCALAR_WAZE_BOUNDARY.md](docs/SCALAR_WAZE_BOUNDARY.md) — Math/interpretation separation
- [docs/NON_CLAIMS.md](docs/NON_CLAIMS.md) — Hard boundary (what we do NOT claim)
- [docs/CLAIMS_REGISTER.md](docs/CLAIMS_REGISTER.md) — Explicit claim categorization
- [PROPRIETARY-NOTICE.md](PROPRIETARY-NOTICE.md) — IP boundaries

### IP Protection
- [PROPRIETARY-NOTICE.md](PROPRIETARY-NOTICE.md) — Open trust layer, closed engine

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
- **Makefile**: `make status`, `make docs-verify`, `make test`, `make lint`, `make boundary`, `make contracts`
- **Export Evidence**: `python -m cli.main export-evidence` — Generate audit bundles
- **Boundary Gate**: `make boundary` — Verify math/interpretation separation
- **CI Workflows**: Main CI, boundary gate (auto-enforced on PR/push)

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

## Recent Updates

### 2026-01-18: Ethereum v0.1.1 + RFC6979 + Boundary Enforcement

**Ethereum Bridge Hardening (v0.1.1):**
- ✅ Fail-closed server architecture (STRICT_CHAIN, STRICT_REVOCATION)
- ✅ Bytecode integrity verification (contract code hash checking)
- ✅ Canonical geocommit computation (PREFIX_V1 domain separation)
- ✅ FastAPI middleware gate (pre-generation enforcement)
- ✅ Privacy-safe metrics (system health only, no user data)
- ✅ Comprehensive tests (18/18 passing)

**RFC6979 Deterministic ECDSA:**
- ✅ Audit-grade deterministic signing (no RNG dependency)
- ✅ Low-S normalization (Bitcoin/Ethereum canonical signatures)
- ✅ Domain separation via `extra` parameter (commitment binding)
- ✅ Rejection sampling (no modulo bias)
- ✅ secp256k1 specialized (Ethereum compatible)
- ✅ Comprehensive tests (25/25 passing)
- ✅ Policy documentation ([RFC6979-NONCE-POLICY.md](docs/RFC6979-NONCE-POLICY.md))

**Math/Interpretation Boundary Enforcement:**
- ✅ Formal separation (classical math vs interpretive frameworks)
- ✅ CI-enforced boundary gate (`make boundary`)
- ✅ 3 boundary docs ([SCALAR_WAZE_BOUNDARY.md](docs/SCALAR_WAZE_BOUNDARY.md), [NON_CLAIMS.md](docs/NON_CLAIMS.md), [CLAIMS_REGISTER.md](docs/CLAIMS_REGISTER.md))
- ✅ Clear non-ownership statements (Gaussian explicit formula unchanged)
- ✅ Layering integrity (no upward dependencies)

**Documentation:**
- ✅ [PROPRIETARY-NOTICE.md](PROPRIETARY-NOTICE.md) - IP boundaries (open trust layer, closed engine)
- ✅ [docs/REGULATOR-SUMMARY.md](docs/REGULATOR-SUMMARY.md) - 400+ line compliance doc
- ✅ [docs/WHAT-THIS-IS-NOT.md](docs/WHAT-THIS-IS-NOT.md) - Clear boundary definitions
- ✅ [docs/V0_2_DESIGN_NOTES.md](docs/V0_2_DESIGN_NOTES.md) - Future roadmap
- ✅ [docs/RFC6979-IMPLEMENTATION.md](docs/RFC6979-IMPLEMENTATION.md) - Technical summary

**All updates maintain audit-grade posture. No breaking changes.**

---

### 2026-01-15: Ethics & Documentation

**Ethics & Documentation:**
- Added ethics anchor verification (SHA-256: `65b14d584...`)
- Comprehensive technical glossary with 40+ terms
- Formal mathematical specifications for state mixer and ZK proofs

**Code Implementations:**
- Evidence export command for audit bundle generation
- Documentation verification scripts
- Makefile with convenient build targets

---

## Thread Archive

- [docs/THREAD-2026-01-15.md](docs/THREAD-2026-01-15.md) — January 15, 2026 compilation (ethics doctrine, geo-phase audit, state mixer notes, Halo2 Option A planning)
