"""
Test bytecode lock verification.

Verifies:
- Matching bytecode passes
- Mismatched bytecode raises
"""

from __future__ import annotations

import pytest
from web3 import Web3

from geophase_eth.eth.bytecode_lock import BytecodeLock


class FakeEth:
    """Mock eth module."""

    def __init__(self, code: bytes):
        self._code = code

    def get_code(self, _addr):
        return self._code


class FakeWeb3:
    """Mock Web3 instance."""

    def __init__(self, code: bytes):
        self.eth = FakeEth(code)

    @staticmethod
    def keccak(data: bytes) -> bytes:
        return Web3.keccak(data)


def test_bytecode_lock_matching_passes():
    """Bytecode lock passes when hash matches."""
    code = b"\x60\x60\x60\x40"
    expected = Web3.keccak(code).hex()
    addr = "0x" + "11" * 20

    lock = BytecodeLock(FakeWeb3(code), addr, expected_codehash=expected)
    lock.verify_or_raise()  # Should not raise


def test_bytecode_lock_mismatch_raises():
    """Bytecode lock raises when hash mismatches."""
    code = b"\x60\x60\x60\x40"
    wrong_hash = "0x" + "00" * 32
    addr = "0x" + "11" * 20

    lock = BytecodeLock(FakeWeb3(code), addr, expected_codehash=wrong_hash)

    with pytest.raises(RuntimeError, match="BYTECODE_MISMATCH"):
        lock.verify_or_raise()


def test_bytecode_lock_case_insensitive():
    """Bytecode lock comparison is case-insensitive."""
    code = b"\x60\x60\x60\x40"
    expected_lower = Web3.keccak(code).hex().lower()
    expected_upper = expected_lower.upper()
    addr = "0x" + "11" * 20

    # Both should pass
    BytecodeLock(FakeWeb3(code), addr, expected_lower).verify_or_raise()
    BytecodeLock(FakeWeb3(code), addr, expected_upper).verify_or_raise()
