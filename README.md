# dna-ledger-vault 🧬⛓️🔐

DNA data stays off-chain (encrypted vault). A hash-chained ledger stores:
- Dataset commits (content hash / chunk root)
- Consent grants (purpose, scope, expiry)
- Compute attestations (algo hash + output hash)

This repo is a local prototype. Replace the ledger backend with a real chain later.

## Quickstart
```bash
pip install -r requirements.txt

# Create a dataset commit + encrypt into vault
python -m cli.main commit --dataset ./samples/sample.vcf --out ./state --owner "dave"

# Grant consent
python -m cli.main grant --out ./state --dataset-id <ID> --grantee "researcher_pubkey" --purpose research --days 30

# Attest a compute job
python -m cli.main attest --out ./state --dataset-id <ID> --algo "GWAS-v1" --result ./samples/result.json
```

## Threat model

No raw DNA is placed on-chain/ledger. Only hashes + signed intent records.
