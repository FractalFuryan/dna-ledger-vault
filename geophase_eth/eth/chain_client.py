"""
Base L2 chain client with fail-closed health checks.

Provides:
- Bytecode verification
- Revocation queries
- Attestation queries
- RPC health monitoring
- Non-behavioral metrics
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from web3 import Web3
from web3.contract import Contract

from geophase_eth.eth.bytecode_lock import BytecodeLock
from geophase_eth.eth.metrics import Metrics


# Minimal ABIs (read/write only what we use)
ATTEST_ABI = [
    {
        "type": "function",
        "name": "attestations",
        "stateMutability": "view",
        "inputs": [{"name": "geoCommit", "type": "bytes32"}],
        "outputs": [
            {"name": "ethicsAnchor", "type": "bytes32"},
            {"name": "policyId", "type": "bytes32"},
            {"name": "version", "type": "uint32"},
            {"name": "attestor", "type": "address"},
            {"name": "timestamp", "type": "uint64"},
        ],
    },
    {
        "type": "function",
        "name": "attest",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "geoCommit", "type": "bytes32"},
            {"name": "ethicsAnchor", "type": "bytes32"},
            {"name": "policyId", "type": "bytes32"},
            {"name": "version", "type": "uint32"},
        ],
        "outputs": [],
    },
]

REVOKE_ABI = [
    {
        "type": "function",
        "name": "revoked",
        "stateMutability": "view",
        "inputs": [{"name": "key", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "isRevoked",
        "stateMutability": "view",
        "inputs": [{"name": "key", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "revoke",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "key", "type": "bytes32"}],
        "outputs": [],
    },
]


@dataclass
class ChainClient:
    """
    Base L2 chain client for GeoPhase commitments.
    
    Provides revocation checking, attestation queries, and health monitoring.
    """

    w3: Web3
    attestation: Contract
    revocation: Contract
    metrics: Metrics

    @staticmethod
    def from_env(
        rpc_url: str,
        attest_addr: str,
        revoke_addr: str,
        *,
        metrics: Optional[Metrics] = None,
    ) -> ChainClient:
        """
        Create client from environment configuration.
        
        Args:
            rpc_url: Base RPC endpoint URL
            attest_addr: AnankeAttestationRegistry address
            revoke_addr: AnankeRevocationRegistry address
            metrics: Optional metrics instance
        
        Returns:
            Configured ChainClient
        """
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 8}))
        att = w3.eth.contract(
            address=Web3.to_checksum_address(attest_addr), abi=ATTEST_ABI
        )
        rev = w3.eth.contract(
            address=Web3.to_checksum_address(revoke_addr), abi=REVOKE_ABI
        )
        return ChainClient(
            w3=w3, attestation=att, revocation=rev, metrics=metrics or Metrics()
        )

    def bytecode_lock(self, attest_codehash: str, revoke_codehash: str) -> None:
        """
        Verify deployed contract bytecode matches expected hashes.
        
        Args:
            attest_codehash: Expected attestation registry bytecode hash
            revoke_codehash: Expected revocation registry bytecode hash
        
        Raises:
            RuntimeError: If bytecode mismatch detected
        """
        if attest_codehash:
            BytecodeLock(
                self.w3, self.attestation.address, attest_codehash
            ).verify_or_raise()
        if revoke_codehash:
            BytecodeLock(
                self.w3, self.revocation.address, revoke_codehash
            ).verify_or_raise()

    def ping(self) -> bool:
        """
        Check RPC health by fetching current block number.
        
        Returns:
            True if RPC reachable, False otherwise
        """
        t0 = time.time()
        try:
            _ = self.w3.eth.block_number
            self.metrics.observe("rpc_latency_ms", (time.time() - t0) * 1000.0)
            return True
        except Exception:
            self.metrics.inc("rpc_errors_total")
            return False

    def is_revoked(self, geo_commit: bytes) -> bool:
        """
        Check if commitment is revoked on-chain.
        
        Args:
            geo_commit: 32-byte commitment hash
        
        Returns:
            True if revoked, False otherwise
        
        Raises:
            Exception: If RPC call fails
        """
        t0 = time.time()
        try:
            ok = self.revocation.functions.isRevoked(geo_commit).call()
            self.metrics.observe("revocation_read_ms", (time.time() - t0) * 1000.0)
            return bool(ok)
        except Exception:
            self.metrics.inc("revocation_read_errors_total")
            raise

    def is_attested(self, geo_commit: bytes) -> bool:
        """
        Check if commitment is attested on-chain.
        
        Args:
            geo_commit: 32-byte commitment hash
        
        Returns:
            True if attested (timestamp != 0), False otherwise
        
        Raises:
            Exception: If RPC call fails
        """
        try:
            rec = self.attestation.functions.attestations(geo_commit).call()
            # timestamp is last field (index 4)
            return int(rec[4]) != 0
        except Exception:
            self.metrics.inc("attestation_read_errors_total")
            raise
