"""
Canonical GeoPhase commitment computation.

Domain-separated, version-locked commitment format:
    geoCommit = Keccak256(PREFIX || seed_commit || phaseA_hash || phaseB_hash || policyId || version)

⭕️🛑 Commitment only - never reveals seed, vectors, or outputs.
"""

from __future__ import annotations

from typing import Final

from eth_utils import keccak


PREFIX_V1: Final[bytes] = b"ANANKE_GEO_COMMIT_V1"


def _b32(x: bytes) -> bytes:
    """Validate 32-byte input."""
    if len(x) != 32:
        raise ValueError("expected 32-byte value")
    return x


def compute_geo_commit_v1(
    *,
    seed_commit: bytes,
    phaseA_hash: bytes,
    phaseB_hash: bytes,
    policy_id: bytes,
    version_u32: int,
) -> bytes:
    """
    Compute canonical GeoPhase commitment (v1).
    
    Args:
        seed_commit: SHA-256 hash of (seed || user_nonce)
        phaseA_hash: SHA-256 hash of GeoPhase A parameter vector
        phaseB_hash: SHA-256 hash of GeoPhase B audit vector
        policy_id: SHA-256 hash of policy document
        version_u32: Protocol version (0-4294967295)
    
    Returns:
        32-byte Keccak256 commitment hash
    
    Note:
        Commitment only. Never store seed/vector/media on chain.
        This format is version-locked and domain-separated.
    """
    if not (0 <= version_u32 <= 0xFFFFFFFF):
        raise ValueError("version_u32 out of range")

    blob = (
        PREFIX_V1
        + _b32(seed_commit)
        + _b32(phaseA_hash)
        + _b32(phaseB_hash)
        + _b32(policy_id)
        + int(version_u32).to_bytes(4, "big")
    )
    return keccak(blob)


def to_hex32(b: bytes) -> str:
    """Convert 32-byte value to 0x-prefixed hex string."""
    if len(b) != 32:
        raise ValueError("expected 32-byte value")
    return "0x" + b.hex()
