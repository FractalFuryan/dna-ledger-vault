"""
On-chain revocation and attestation checks.

⭕️🛑 Privacy-safe: queries commitments only, no user data retrieval.
"""

from __future__ import annotations

from typing import Optional

from web3 import Web3
from web3.contract import Contract


# Contract ABIs (minimal, read-only functions)
REVOCATION_ABI = [
    {
        "inputs": [{"internalType": "bytes32", "name": "key", "type": "bytes32"}],
        "name": "isRevoked",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    }
]

ATTESTATION_ABI = [
    {
        "inputs": [{"internalType": "bytes32", "name": "geoCommit", "type": "bytes32"}],
        "name": "isAttested",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "geoCommit", "type": "bytes32"}],
        "name": "getAttestation",
        "outputs": [
            {
                "components": [
                    {"internalType": "bytes32", "name": "ethicsAnchor", "type": "bytes32"},
                    {"internalType": "bytes32", "name": "policyId", "type": "bytes32"},
                    {"internalType": "uint32", "name": "version", "type": "uint32"},
                    {"internalType": "address", "name": "attestor", "type": "address"},
                    {"internalType": "uint64", "name": "timestamp", "type": "uint64"},
                ],
                "internalType": "struct AnankeAttestationRegistry.Attestation",
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
]


class ChainGate:
    """
    On-chain gate for GeoPhase generation/regeneration.
    
    Checks revocation status before allowing operations.
    """

    def __init__(
        self,
        rpc_url: str,
        revocation_address: str,
        attestation_address: Optional[str] = None,
    ):
        """
        Initialize chain gate.
        
        Args:
            rpc_url: Base RPC endpoint
            revocation_address: AnankeRevocationRegistry contract address
            attestation_address: AnankeAttestationRegistry contract address (optional)
        """
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        assert self.w3.is_connected(), f"Failed to connect to RPC: {rpc_url}"

        self.revocation = self.w3.eth.contract(
            address=Web3.to_checksum_address(revocation_address),
            abi=REVOCATION_ABI,
        )

        self.attestation: Optional[Contract] = None
        if attestation_address:
            self.attestation = self.w3.eth.contract(
                address=Web3.to_checksum_address(attestation_address),
                abi=ATTESTATION_ABI,
            )

    def is_revoked(self, geo_commit: bytes) -> bool:
        """
        Check if commitment is revoked on-chain.
        
        Args:
            geo_commit: 32-byte commitment hash
        
        Returns:
            True if revoked, False otherwise
        """
        assert len(geo_commit) == 32, "geo_commit must be 32 bytes"
        return self.revocation.functions.isRevoked(geo_commit).call()

    def is_attested(self, geo_commit: bytes) -> bool:
        """
        Check if commitment is attested on-chain.
        
        Args:
            geo_commit: 32-byte commitment hash
        
        Returns:
            True if attested, False otherwise
        
        Raises:
            RuntimeError: If attestation registry not configured
        """
        if not self.attestation:
            raise RuntimeError("Attestation registry not configured")

        assert len(geo_commit) == 32, "geo_commit must be 32 bytes"
        return self.attestation.functions.isAttested(geo_commit).call()

    def get_attestation(self, geo_commit: bytes) -> dict:
        """
        Get attestation details for commitment.
        
        Args:
            geo_commit: 32-byte commitment hash
        
        Returns:
            Attestation dict with fields:
                - ethicsAnchor (bytes32)
                - policyId (bytes32)
                - version (uint32)
                - attestor (address)
                - timestamp (uint64)
        
        Raises:
            RuntimeError: If attestation registry not configured
        """
        if not self.attestation:
            raise RuntimeError("Attestation registry not configured")

        assert len(geo_commit) == 32, "geo_commit must be 32 bytes"
        result = self.attestation.functions.getAttestation(geo_commit).call()

        return {
            "ethicsAnchor": result[0],
            "policyId": result[1],
            "version": result[2],
            "attestor": result[3],
            "timestamp": result[4],
        }

    def check_before_generation(self, geo_commit: bytes) -> None:
        """
        Gate check before generation/regeneration.
        
        Args:
            geo_commit: 32-byte commitment hash
        
        Raises:
            ValueError: If commitment is revoked
        """
        if self.is_revoked(geo_commit):
            raise ValueError(f"Commitment is revoked: {geo_commit.hex()}")
