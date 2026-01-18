"""
Bytecode integrity verification - fail-closed contract trust.

Compares deployed bytecode hash to expected value.
Prevents silent contract redeployment or proxy swap.
"""

from __future__ import annotations

from dataclasses import dataclass

from web3 import Web3


def keccak_hex(data: bytes) -> str:
    """Compute Keccak256 hash and return hex string."""
    return Web3.keccak(data).hex()


@dataclass(frozen=True)
class BytecodeLock:
    """
    Fail-closed contract integrity check.
    
    Compares deployed bytecode (eth_getCode) keccak hash to expected hash.
    Raises RuntimeError if mismatch detected.
    """

    w3: Web3
    contract_address: str
    expected_codehash: str  # 0x-prefixed keccak256(code)

    def fetch_codehash(self) -> str:
        """Fetch deployed bytecode and compute its hash."""
        code = self.w3.eth.get_code(Web3.to_checksum_address(self.contract_address))
        return keccak_hex(bytes(code))

    def verify_or_raise(self) -> None:
        """
        Verify bytecode hash matches expected value.
        
        Raises:
            RuntimeError: If deployed bytecode hash doesn't match expected
        """
        got = self.fetch_codehash().lower()
        exp = self.expected_codehash.lower()
        if got != exp:
            raise RuntimeError(
                f"BYTECODE_MISMATCH {self.contract_address} "
                f"expected={exp} got={got}"
            )
