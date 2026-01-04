# dna-ledger-vault 🧬⛓️🔐
**DNA stays off-chain (encrypted).** A hash-chained, signed ledger stores only:
- Dataset fingerprints (hashes + Merkle-ish root)
- Consent grants (purpose-scoped, time-limited)
- Revocations (explicit on-ledger truth)
- Compute attestations (algo + output hashing)
- Key rotation events (forward secrecy + post-compromise safety)

This is the "only kind" of DNA blockchain tech that doesn't blow up privacy:
✅ Zero raw DNA on-chain/ledger  
✅ Cryptographic provenance on every entry  
✅ Consent enforced before compute is recorded  

---

## Threat model (non-negotiable)
DNA is inherently identifying. This repo **never** stores raw sequences/variants in the ledger.
Only tamper-evident proofs and permissions are recorded.

---

## What's implemented (vNext)
### 🔏 Cryptographic Provenance (Ed25519)
Every ledger payload is **signed by its creator**.
Ledger verification checks:
- Hash-chain integrity
- Signature validity on every block

### 🧾 Consent + Revocation (Policy Engine)
- Consent grants: purpose-scoped + expiring
- Revocations: explicit events (no ambiguity)
- Compute attestations require a valid, unrevoked grant

### 🗝️ Real Access Control (X25519 Wrap)
- DNA dataset is encrypted in the vault with a per-dataset **DEK**
- DEK is **wrapped** to grantee public keys (X25519 ECDH + HKDF)
- Only the grantee can unwrap (no shared secrets)

### 🔁 Key Rotation (Forward Secrecy)
- Rotate DEKs (re-encrypt vault)
- Automatically re-wrap to **active** grantees only
- Old DEKs become useless after rotation

---

## Repo layout
- `vault/` — off-chain encryption + vault storage + DEK wrapping
- `dna_ledger/` — hashing, models, signed hash-chained ledger
- `cli/` — command-line workflow

---

## Install
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

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

## Commands

* `init-identities` — generate Ed25519 + X25519 keypairs for an identity
* `commit` — commit a dataset (hashes + Merkle-ish root), encrypt to vault, signed entry
* `grant` — record consent grant, wrap DEK to grantee, signed entry
* `revoke-consent` — explicit revocation event, signed entry
* `attest` — record compute attestation (requires active, unrevoked consent), signed entry
* `rotate-key` — rotate DEK, re-encrypt vault, re-wrap to active grantees, signed rotation event
* `verify` — verify hash chain + signatures

---

## Next tiers (optional)

* **Merkle**: inclusion proofs for specific chunks/SNP buckets
* **ZK**: interface for "prove marker without revealing genome"
* **Chain**: Ethereum/Solana contracts + on-chain attestations
