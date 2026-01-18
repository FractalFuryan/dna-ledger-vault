"""
GeoPhase Ethereum Bridge

⭕️🛑 Privacy-safe on-chain attestation layer.
Stores commitments only - no media, no likeness, no user data.
"""

# Legacy imports (deprecated, use geophase_eth.eth.*)
try:
    from geophase_eth.chain_check import ChainGate
    from geophase_eth.geocommit import (
        compute_geo_commit,
        create_phase_hashes,
        create_seed_commit,
        sha256_hash,
    )
except ImportError:
    # If old modules don't exist, that's OK
    pass

__all__ = [
    "ChainGate",
    "compute_geo_commit",
    "create_phase_hashes",
    "create_seed_commit",
    "sha256_hash",
]
