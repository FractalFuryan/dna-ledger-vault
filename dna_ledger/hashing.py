from __future__ import annotations
import hashlib
from typing import Iterable, List, Tuple

CHUNK = 1024 * 1024  # 1MB

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: str) -> Tuple[str, int]:
    h = hashlib.sha256()
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
            out.append(sha256(chunk))
    return out

def merkle_root(leaves: List[str]) -> str:
    """
    Simple Merkle-ish root over hex digests (not domain-separated; good enough for v0).
    """
    if not leaves:
        return sha256(b"")
    level = leaves[:]
    while len(level) > 1:
        nxt = []
        it = iter(level)
        for a in it:
            b = next(it, a)  # duplicate last if odd
            nxt.append(sha256(bytes.fromhex(a) + bytes.fromhex(b)))
        level = nxt
    return level[0]
