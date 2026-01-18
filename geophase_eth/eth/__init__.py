"""
GeoPhase Ethereum Integration - Trust Layer

⭕️🛑 Privacy-safe on-chain attestation.
Commitments only. No media, no likeness, no user data.
"""

from geophase_eth.eth.bytecode_lock import BytecodeLock
from geophase_eth.eth.chain_client import ChainClient
from geophase_eth.eth.geocommit import compute_geo_commit_v1, to_hex32
from geophase_eth.eth.metrics import Metrics
from geophase_eth.eth.settings import Settings

__all__ = [
    "BytecodeLock",
    "ChainClient",
    "compute_geo_commit_v1",
    "to_hex32",
    "Metrics",
    "Settings",
]
