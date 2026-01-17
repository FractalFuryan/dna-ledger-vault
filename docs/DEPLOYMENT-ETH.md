# GeoPhase ↔ Ethereum Bridge — Deployment Guide

⭕️🛑 **Privacy-safe on-chain attestation layer**

---

## Prerequisites

1. **Foundry** (Solidity toolchain)
   ```bash
   make install-foundry
   ```

2. **Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Base wallet** with testnet ETH
   - Get Base Sepolia ETH from [faucet](https://www.coinbase.com/faucets/base-ethereum-sepolia-faucet)

---

## Deployment Steps

### 1. Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:
```bash
PRIVATE_KEY=0x...  # Your deployer private key (DO NOT COMMIT)
BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
```

### 2. Build Contracts

```bash
make contracts
```

This compiles:
- `AnankeAttestationRegistry.sol`
- `AnankeRevocationRegistry.sol`

### 3. Deploy to Base Sepolia (Testnet)

```bash
make deploy-sepolia
```

Output:
```
Deploying from: 0x...
Balance: 0.1 ETH

Deploying AnankeAttestationRegistry...
✅ AnankeAttestationRegistry: 0x1234...

Deploying AnankeRevocationRegistry...
✅ AnankeRevocationRegistry: 0x5678...

Update .env with these addresses:
ATTESTATION_REGISTRY_ADDRESS=0x1234...
REVOCATION_REGISTRY_ADDRESS=0x5678...
```

### 4. Update .env with Deployed Addresses

```bash
ATTESTATION_REGISTRY_ADDRESS=0x1234...
REVOCATION_REGISTRY_ADDRESS=0x5678...
```

### 5. Verify Deployment

```bash
python -m geophase_eth.example
```

Expected output:
```
Seed commit: a3f2...
Phase A hash: b8c1...
Phase B hash: 7d9e...
Policy ID: 3f4a...

GeoPhase commitment: 6e5d...

Checking revocation status...
✅ Not revoked - safe to generate
Attestation status: ⏳ Not yet attested

✅ Workflow complete
```

---

## Production Deployment (Base Mainnet)

### 1. Get Mainnet ETH

Transfer ~0.01 ETH to deployer address (covers deployment gas).

### 2. Update .env

```bash
BASE_RPC_URL=https://mainnet.base.org
BASESCAN_API_KEY=...  # For contract verification
```

### 3. Deploy

```bash
python -m geophase_eth.deploy --network base
```

### 4. Verify Contracts on Basescan

```bash
forge verify-contract \
  --chain-id 8453 \
  --etherscan-api-key $BASESCAN_API_KEY \
  <ATTESTATION_ADDRESS> \
  contracts/AnankeAttestationRegistry.sol:AnankeAttestationRegistry

forge verify-contract \
  --chain-id 8453 \
  --etherscan-api-key $BASESCAN_API_KEY \
  <REVOCATION_ADDRESS> \
  contracts/AnankeRevocationRegistry.sol:AnankeRevocationRegistry
```

---

## Usage Integration

### In Python (Server-Side)

```python
from geophase_eth import (
    ChainGate,
    compute_geo_commit,
    create_seed_commit,
    create_phase_hashes,
    sha256_hash,
)

# Before generation
gate = ChainGate(
    rpc_url="https://mainnet.base.org",
    revocation_address="0x...",
    attestation_address="0x...",
)

geo_commit = compute_geo_commit(...)
gate.check_before_generation(geo_commit)  # Raises if revoked

# ... proceed with generation ...
```

### From Smart Contracts

```solidity
// External contract can verify attestation
interface IAnankeAttestationRegistry {
    function isAttested(bytes32 geoCommit) external view returns (bool);
    function getAttestation(bytes32 geoCommit) external view returns (
        bytes32 ethicsAnchor,
        bytes32 policyId,
        uint32 version,
        address attestor,
        uint64 timestamp
    );
}

// Check before minting NFT, etc.
IAnankeAttestationRegistry attestation = IAnankeAttestationRegistry(0x...);
require(attestation.isAttested(geoCommit), "not attested");
```

---

## Cost Estimates (Base Mainnet)

- **Deployment**: ~$10-50 (one-time)
- **Attestation**: ~$0.01-0.10 per transaction
- **Revocation**: ~$0.01-0.10 per transaction
- **Queries (read)**: Free

---

## Security Checklist

Before production:

- [ ] Test on Base Sepolia with full workflow
- [ ] Audit contracts with Slither: `slither contracts/`
- [ ] Verify ethics anchor matches: `65b14d584f5a5fd070fe985eeb86e14cb3ce56a4fc41fd9e987f2259fe1f15c1`
- [ ] Set up monitoring for unexpected attestations
- [ ] Document contract addresses in [docs/GEO-COMMIT-SPEC.md](GEO-COMMIT-SPEC.md)
- [ ] Verify contracts on Basescan
- [ ] Test RPC failover logic
- [ ] Review [docs/THREAT-MODEL-ETH.md](THREAT-MODEL-ETH.md)

---

## Troubleshooting

### "Failed to connect to RPC"
- Check RPC URL in `.env`
- Try alternative RPC: `https://base.llamarpc.com` or self-host

### "Insufficient funds"
- Get testnet ETH from [Base Sepolia faucet](https://www.coinbase.com/faucets/base-ethereum-sepolia-faucet)
- For mainnet, ensure deployer has >0.01 ETH

### "Contract artifact not found"
- Run `make contracts` to compile Solidity contracts

### "Already attested"
- Attestation is one-shot (immutable)
- Use different `geoCommit` for new attestations

---

## Next Steps (v0.2)

- [ ] Add revocation authorization (signature-gated)
- [ ] Implement EIP-712 procedural auth tokens
- [ ] Add batch attestation support
- [ ] Integrate with Halo2 ZK proofs (Option A)
- [ ] Add AnankeSeedRightsNFT (regeneration rights)

---

## References

- [Base Network Docs](https://docs.base.org/)
- [Foundry Book](https://book.getfoundry.sh/)
- [GEO-COMMIT-SPEC.md](GEO-COMMIT-SPEC.md)
- [THREAT-MODEL-ETH.md](THREAT-MODEL-ETH.md)
