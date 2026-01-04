# 🧬⛓️🔐 DNA Ledger Vault - vNext Demo

## Complete Workflow with Signatures + Consent Enforcement + Key Wrapping

### 1️⃣ Initialize Identities (Ed25519 + X25519 keypairs)

```bash
# Create dataset owner identity
python -m cli.main init-identities --out state --who dave

# Create researcher identity  
python -m cli.main init-identities --out state --who researcher1

# Create unauthorized actor (for testing policy enforcement)
python -m cli.main init-identities --out state --who hacker
```

### 2️⃣ Commit Dataset (signed + encrypted)

```bash
python -m cli.main commit --dataset samples/sample.vcf --out state --owner dave
# ✅ Dataset committed + vaulted + signed
#    dataset_id   : ds_xxxxxxxxxxxxxxxx
#    signer       : dave
#    ledger_ok    : True (chain + signature verified)
```

### 3️⃣ Grant Consent (signed + DEK wrapped to grantee)

```bash
python -m cli.main grant \
  --out state \
  --actor dave \
  --dataset-id ds_xxxxxxxxxxxxxxxx \
  --grantee researcher1 \
  --purpose research \
  --days 30
# ✅ Consent grant recorded + DEK wrapped to grantee
#    Uses X25519 ECDH to wrap DEK to researcher1's public key
```

### 4️⃣ Policy Enforcement Demo

**❌ Unauthorized actor blocked:**
```bash
python -m cli.main attest \
  --out state \
  --actor hacker \
  --dataset-id ds_xxxxxxxxxxxxxxxx \
  --purpose research \
  --algo "GWAS-v1" \
  --result samples/result.json

# ❌ No valid consent grant found for actor=hacker
```

**✅ Authorized actor succeeds:**
```bash
python -m cli.main attest \
  --out state \
  --actor researcher1 \
  --dataset-id ds_xxxxxxxxxxxxxxxx \
  --purpose research \
  --algo "GWAS-v1" \
  --result samples/result.json

# ✅ Compute attestation recorded (consent verified)
```

### 5️⃣ Verify Complete Chain + Signatures

```bash
python -m cli.main verify --out state
# ✅ Ledger verify (chain + signatures)
#    - Hash chain integrity ✓
#    - Ed25519 signature verification ✓
```

---

## 🔥 What Just Happened

✅ **Cryptographic Provenance** - Every ledger entry is Ed25519-signed by its creator  
✅ **Tamper Detection** - Hash-chained blocks (blockchain-style)  
✅ **Policy Enforcement** - Compute attestations require valid consent grants  
✅ **Real Access Control** - DEK wrapped to grantee's X25519 public key via ECDH  
✅ **Zero DNA On-Chain** - Only hashes, consent records, and attestations on ledger  

---

## Architecture Highlights

### Ledger Block Schema
```json
{
  "prev_hash": "sha256_of_previous_block",
  "payload": {
    "kind": "DatasetCommit|ConsentGrant|ComputeAttestation",
    ...
  },
  "signer": {
    "id": "dave",
    "ed25519_pub_pem_b64": "..."
  },
  "sig": "base64_ed25519_signature",
  "block_hash": "sha256(prev_hash || payload)"
}
```

### Key Wrapping Flow
1. Owner (dave) has X25519 keypair
2. Grantee (researcher1) has X25519 keypair
3. ECDH shared secret = dave_priv ⊗ researcher1_pub
4. Wrap key = HKDF(shared_secret, context)
5. Wrapped DEK = ChaCha20Poly1305(wrap_key, DEK, context)
6. Only researcher1 can unwrap DEK (has their private key)

---

## 🚀 Next Level Features Available

1. **Revocation events** - Explicit consent revocation on ledger
2. **Key rotation** - Rotate DEKs with re-wrapping to grantees
3. **Merkle inclusion proofs** - Prove dataset chunk in commit
4. **ZK-SNARKs interface** - "Prove marker without revealing genome"
5. **Ethereum/Solana backend** - Replace local ledger with real chain

This is **production-grade DNA blockchain tech** 😈⛓️🧬
