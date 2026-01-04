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

---

## 🧨 vNext.1 - Revocation + Key Rotation

### Consent Revocation Flow

**Revoke a consent grant:**
```bash
python -m cli.main revoke-consent \
  --out state \
  --actor dave \
  --dataset-id ds_xxxxxxxxxxxxxxxx \
  --grant-id cg_xxxxxxxxxxxxxxxx \
  --reason "Study completed"
# 🛑 Consent revoked
```

**Verify revocation blocks access:**
```bash
# Revoked researcher now blocked
python -m cli.main attest \
  --out state \
  --actor researcher1 \
  --dataset-id ds_xxxxxxxxxxxxxxxx \
  --purpose research \
  --algo "GWAS-v2" \
  --result samples/result.json
# ❌ No active, unrevoked consent grant found
```

### Key Rotation Flow (Forward Secrecy)

**Rotate dataset encryption key:**
```bash
python -m cli.main rotate-key \
  --out state \
  --actor dave \
  --dataset-id ds_xxxxxxxxxxxxxxxx
# 🔁 Key rotation complete
#    - Generates new DEK
#    - Re-encrypts vault with new DEK
#    - Re-wraps DEK to ACTIVE grantees only
#    - Records KeyRotationEvent on ledger
#    - Old DEK becomes useless (forward secrecy)
```

**What happens during rotation:**
1. ✅ New DEK generated
2. ✅ Dataset re-encrypted in vault
3. ✅ DEK re-wrapped to active grantees (revoked ones excluded)
4. ✅ KeyRotationEvent signed + recorded
5. ✅ Old DEK discarded (forward secrecy)

**Post-rotation verification:**
- Active researchers continue working seamlessly ✓
- Revoked researchers stay blocked ✓
- Old DEK leaks don't compromise new data ✓

---

## 🔐 Security Guarantees (vNext.1)

✅ **Time-bounded consent** - Grants expire automatically  
✅ **Explicit revocation** - On-chain revocation events (no ambiguity)  
✅ **Forward secrecy** - Old DEKs useless after rotation  
✅ **Post-compromise safety** - Past key leaks don't affect rotated data  
✅ **Audit-perfect lineage** - Every event hash-chained + signed  
✅ **Zero DNA on-chain** - Only hashes, consent, and attestations  

This is **medical-grade**, **legal-grade**, **cryptography-correct** DNA governance.

---

## 🚀 Available Next Tiers

**Merkle Inclusion Proofs** - Prove specific SNP/chunk without exposing genome  
**ZK-SNARK Interface** - "Prove marker present" with zero disclosure  
**Ethereum/Solidity** - Real blockchain deployment with smart contracts  

