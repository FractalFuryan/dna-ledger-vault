# Ethereum Bridge Threat Model

⭕️🛑 **Privacy-safe on-chain attestation threat analysis**

---

## Scope

This threat model covers the Ethereum bridge for GeoPhase commitments:
- `AnankeAttestationRegistry` (on-chain)
- `AnankeRevocationRegistry` (on-chain)
- Python integration (`geophase_eth`)

---

## Trust Assumptions

### Trusted
- Ethereum/Base consensus (51% attack threshold)
- Solidity compiler correctness
- Web3.py library correctness
- User's local key management

### Untrusted
- Contract deployer (after deployment, immutable)
- Attestors (anyone can attest)
- Revokers (anyone can revoke their own commitments)
- RPC providers (can censor, lie about state)

---

## Threat Categories

### 1. Privacy Leakage

**Threat:** Commitment correlation reveals user behavior  
**Mitigation:**
- Commitments are cryptographically hiding
- No direct user identity linkage
- Use fresh addresses per attestation if privacy required

**Threat:** Timing correlation (attestation timestamp)  
**Mitigation:**
- Batch attestations if timing sensitivity exists
- Use delayed attestation (attest hours/days after generation)

**Threat:** RPC provider logging  
**Mitigation:**
- Use privacy-preserving RPC (e.g., via Tor, VPN)
- Self-host Base node for maximum privacy

### 2. Revocation Abuse

**Threat:** Attacker revokes others' commitments  
**Mitigation:**
- ❌ **Current:** Anyone can revoke any commitment (no access control)
- ✅ **Future (v0.2):** Add revocation authorization (signature required)

**Threat:** Front-running revocation (MEV)  
**Mitigation:**
- Use private transaction pool (e.g., Flashbots Protect)
- Accept that revocation is public and immediate

**Threat:** Spam revocation (griefing)  
**Mitigation:**
- Add gas costs as natural rate limit
- Monitor for abuse patterns
- Consider fee-based revocation in future

### 3. Attestation Integrity

**Threat:** False attestation (wrong ethics anchor)  
**Mitigation:**
- Client-side verification of ethics anchor before trusting attestation
- Automated monitoring of attestations with unexpected anchors

**Threat:** Attestation denial (censorship)  
**Mitigation:**
- Use multiple RPC endpoints
- Self-host Base node
- Accept that censorship-resistant attestation requires decentralization trade-offs

**Threat:** Replay attack (reuse old commitment)  
**Mitigation:**
- One-shot attestation (cannot re-attest same commitment)
- Include timestamp in verification logic

### 4. Smart Contract Risks

**Threat:** Reentrancy  
**Status:** ✅ No reentrancy vectors (no external calls, no ETH transfers)

**Threat:** Integer overflow/underflow  
**Status:** ✅ Solidity 0.8.20+ has built-in overflow checks

**Threat:** Access control bypass  
**Status:** ⚠️ No access control (by design for v0.1)

**Threat:** Gas griefing  
**Status:** ✅ Fixed gas costs, no loops, no unbounded operations

**Threat:** Upgrade risk  
**Status:** ✅ No upgradeability (immutable contracts)

### 5. Off-chain Integration Risks

**Threat:** Seed leakage via commitment computation  
**Mitigation:**
- Never log raw seed values
- Use secure memory (consider `mlock` for sensitive data)
- Clear seed from memory after commitment creation

**Threat:** RPC injection  
**Mitigation:**
- Validate RPC URL format
- Use TLS for RPC connections
- Pin certificate if using custom RPC

**Threat:** Dependency supply chain attack  
**Mitigation:**
- Lock dependencies (`requirements-lock.txt`)
- Audit Web3.py and eth-utils versions
- Use dependency scanning (Dependabot, Snyk)

### 6. Economics & Incentives

**Threat:** Gas price manipulation  
**Mitigation:**
- Use Base L2 (low gas costs, ~$0.01-0.10 per tx)
- Batch operations if cost-sensitive

**Threat:** Contract deployment cost  
**Status:** One-time cost (~$10-50 on Base)

**Threat:** Ongoing operation costs  
**Status:** Per-attestation ~$0.01-0.10 (negligible for most use cases)

---

## Attack Scenarios

### Scenario 1: Malicious Attestor

**Attack:** Attacker attests to commitments with wrong ethics anchor  
**Impact:** Low (clients verify anchor, ignore invalid attestations)  
**Likelihood:** Medium  
**Severity:** Low  

### Scenario 2: Revocation Griefing

**Attack:** Attacker revokes all commitments (spam attack)  
**Impact:** Medium (DoS on revocation registry)  
**Likelihood:** Low (gas costs make this expensive)  
**Severity:** Medium  
**Mitigation (v0.2):** Add revocation authorization

### Scenario 3: RPC Censorship

**Attack:** RPC provider censors attestation/revocation transactions  
**Impact:** Medium (temporary unavailability)  
**Likelihood:** Low  
**Severity:** Medium  
**Mitigation:** Use multiple RPC endpoints, self-host node

### Scenario 4: Front-running Generation

**Attack:** Attacker observes mempool, attests to commitment before user  
**Impact:** Low (doesn't prevent user's generation, just timestamps)  
**Likelihood:** Low (no financial incentive)  
**Severity:** Low  

---

## Residual Risks (Accepted)

1. **Public observability**: All attestations/revocations are public
   - **Accepted:** Trade-off for decentralization and verifiability

2. **No revocation authorization (v0.1)**: Anyone can revoke any commitment
   - **Accepted:** Simplified model for v0.1, addressed in v0.2

3. **RPC trust**: Clients trust RPC provider for state queries
   - **Accepted:** Users can self-host for trustless verification

4. **Gas cost variability**: Base gas prices fluctuate
   - **Accepted:** L2 costs remain low (<$1 per operation)

---

## Security Checklist

Before production deployment:

- [ ] Audit contracts with Slither/Mythril
- [ ] Test revocation race conditions
- [ ] Verify ethics anchor matches expected value
- [ ] Test RPC failover logic
- [ ] Implement rate limiting on client side
- [ ] Add monitoring for unexpected attestations
- [ ] Document contract addresses in production
- [ ] Set up block explorer verification (Basescan)
- [ ] Test with Base Sepolia testnet first
- [ ] Review gas estimation logic

---

## Incident Response

### Detected: Invalid ethics anchor attestation

1. Alert monitoring system
2. Blacklist attestor address (client-side)
3. Document incident
4. No on-chain action required (clients ignore invalid attestations)

### Detected: Mass revocation spam

1. Monitor gas costs
2. Identify attacker addresses
3. Consider contract upgrade path (future)
4. Document for v0.2 access control implementation

### Detected: RPC compromise

1. Switch to backup RPC endpoint
2. Verify state via block explorer
3. Consider self-hosting node
4. Document incident

---

## References

- [Smart Contract Security Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [Base Network Security](https://docs.base.org/security)
- [DNA Ledger Vault Security](SECURITY.md)
