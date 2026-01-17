"""
GeoPhase Ethereum Bridge

⭕️🛑 Privacy-safe on-chain attestation layer.
Stores commitments only - no media, no likeness, no user data.
"""

from geophase_eth.chain_check import ChainGate
from geophase_eth.geocommit import (
    compute_geo_commit,
    create_phase_hashes,
    create_seed_commit,
    sha256_hash,
)

__all__ = [
    "ChainGate",
    "compute_geo_commit",
    "create_phase_hashes",
    "create_seed_commit",
    "sha256_hash",
]
