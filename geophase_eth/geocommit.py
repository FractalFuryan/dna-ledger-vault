"""
GeoPhase commitment generation for Ethereum attestation.

⭕️🛑 Privacy-safe: commitments only, no media, no likeness, no user data.
"""

from __future__ import annotations

import hashlib
from typing import Tuple

from eth_utils import keccak


def sha256_hash(data: bytes) -> bytes:
    """SHA-256 hash of data."""
    return hashlib.sha256(data).digest()


def compute_geo_commit(
    seed_commit: bytes,
    phase_a_hash: bytes,
    phase_b_hash: bytes,
    policy_id: bytes,
    version: int,
) -> bytes:
    """
    Compute GeoPhase commitment for on-chain attestation.
    
    Args:
        seed_commit: SHA-256 hash of (seed || user_nonce)
        phase_a_hash: SHA-256 hash of GeoPhase A parameter vector
        phase_b_hash: SHA-256 hash of GeoPhase B audit vector
        policy_id: SHA-256 hash of policy document
        version: Protocol version number (uint32)
    
    Returns:
        bytes32 commitment (Keccak256 hash)
    
    Example:
        >>> seed = b"example_seed"
        >>> nonce = b"user_nonce_123"
        >>> seed_commit = sha256_hash(seed + nonce)
        >>> phase_a = b"phase_a_vector_data"
        >>> phase_b = b"phase_b_vector_data"
        >>> policy = b"policy_doc_v1"
        >>> commit = compute_geo_commit(
        ...     seed_commit=sha256_hash(seed + nonce),
        ...     phase_a_hash=sha256_hash(phase_a),
        ...     phase_b_hash=sha256_hash(phase_b),
        ...     policy_id=sha256_hash(policy),
        ...     version=1
        ... )
    """
    assert len(seed_commit) == 32, "seed_commit must be 32 bytes"
    assert len(phase_a_hash) == 32, "phase_a_hash must be 32 bytes"
    assert len(phase_b_hash) == 32, "phase_b_hash must be 32 bytes"
    assert len(policy_id) == 32, "policy_id must be 32 bytes"
    assert 0 <= version < 2**32, "version must fit in uint32"

    # Domain-separated commitment
    domain = b"ANANKE_GEO_COMMIT_V1"
    version_bytes = version.to_bytes(4, "big")

    commitment_input = (
        domain +
        seed_commit +
        phase_a_hash +
        phase_b_hash +
        policy_id +
        version_bytes
    )

    return keccak(commitment_input)


def create_seed_commit(seed: bytes, user_nonce: bytes) -> bytes:
    """
    Create seed commitment from seed and user nonce.
    
    Args:
        seed: Random seed bytes
        user_nonce: User-specific nonce for binding
    
    Returns:
        SHA-256 hash commitment
    """
    return sha256_hash(seed + user_nonce)


def create_phase_hashes(
    phase_a_vector: bytes,
    phase_b_vector: bytes,
) -> Tuple[bytes, bytes]:
    """
    Create phase vector hashes.
    
    Args:
        phase_a_vector: GeoPhase A parameter vector (serialized)
        phase_b_vector: GeoPhase B audit vector (serialized)
    
    Returns:
        (phase_a_hash, phase_b_hash) tuple
    """
    return (
        sha256_hash(phase_a_vector),
        sha256_hash(phase_b_vector),
    )
