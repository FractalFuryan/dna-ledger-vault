from __future__ import annotations

import hashlib
import json
from typing import Any, List, Tuple

try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False

CHUNK = 1024 * 1024  # 1MB

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def blake3_hash(data: bytes) -> str:
    """BLAKE3 hash (faster, parallel-friendly, forward-leaning primitive)."""
    if not HAS_BLAKE3:
        raise RuntimeError("blake3 library not installed")
    return blake3.blake3(data).hexdigest()

def canonical(obj: Any) -> bytes:
    """Canonical JSON serialization for deterministic hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

# Domain-separated hashing (prevents structural collisions)
def h_leaf(chunk: bytes) -> str:
    """Hash a data chunk (leaf node in Merkle tree)."""
    return sha256(b"DNALEAF\x00" + chunk)

def h_node(left_hex: str, right_hex: str) -> str:
    """Hash two child nodes (internal Merkle node)."""
    return sha256(b"DNANODE\x00" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))

def h_node_blake3(left_hex: str, right_hex: str) -> str:
    """BLAKE3 hash of two child nodes (internal Merkle node)."""
    return blake3_hash(b"DNANODE\x00" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))

def h_payload(payload: dict) -> str:
    """Hash a ledger payload (for signing)."""
    return sha256(b"PAYLOAD\x00" + canonical(payload))

def h_block(block_header: dict) -> str:
    """Hash a complete block header (prev+payload+signer+sig)."""
    return sha256(b"BLOCK\x00" + canonical(block_header))

def h_commit(commit: dict) -> str:
    """Hash a dataset commit (for binding grants to specific versions)."""
    return sha256(b"DATASETCOMMIT\x00" + canonical(commit))

def sha256_file(path: str) -> Tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n

def blake3_file(path: str) -> Tuple[str, int]:
    """BLAKE3 file hash (parallel-friendly, faster than SHA-256)."""
    if not HAS_BLAKE3:
        raise RuntimeError("blake3 library not installed")
    h = blake3.blake3()
    n = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n

def chunk_hashes(path: str) -> List[str]:
    out = []
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            out.append(h_leaf(chunk))  # domain-separated leaf hash
    return out

def merkle_root(leaves: List[str]) -> str:
    """
    Domain-separated Merkle tree root.
    Uses h_node for internal nodes, h_leaf already applied to leaves.
    """
    if not leaves:
        return sha256(b"DNAEMPTY\x00")
    level = leaves[:]
    while len(level) > 1:
        nxt = []
        it = iter(level)
        for a in it:
            b = next(it, a)  # duplicate last if odd
            nxt.append(h_node(a, b))
        level = nxt
    return level[0]

def merkle_root_blake3(leaves: List[str]) -> str:
    """
    BLAKE3-based Merkle tree root (supplemental for performance).
    Uses h_node_blake3 for internal nodes.
    """
    if not HAS_BLAKE3:
        raise RuntimeError("blake3 library not installed")
    if not leaves:
        return blake3_hash(b"DNAEMPTY\x00")
    level = leaves[:]
    while len(level) > 1:
        nxt = []
        it = iter(level)
        for a in it:
            b = next(it, a)  # duplicate last if odd
            nxt.append(h_node_blake3(a, b))
        level = nxt
    return level[0]
