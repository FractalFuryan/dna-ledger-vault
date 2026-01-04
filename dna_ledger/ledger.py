from __future__ import annotations
import json, os, hashlib
from typing import Any, Dict, List, Optional
from .hashing import sha256

def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

class HashChainedLedger:
    """
    Minimal "blockchain" ledger:
    Each entry is a block with:
      - prev_hash
      - payload (the record)
      - block_hash = sha256(prev_hash || canonical(payload))
    Stored as JSONL.
    """
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            open(path, "wb").close()

    def _read_blocks(self) -> List[Dict[str, Any]]:
        blocks = []
        with open(self.path, "rb") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                blocks.append(json.loads(line))
        return blocks

    def tip_hash(self) -> str:
        blocks = self._read_blocks()
        return blocks[-1]["block_hash"] if blocks else sha256(b"GENESIS")

    def append(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        prev = self.tip_hash()
        block_hash = sha256(prev.encode() + canonical(payload))
        block = {"prev_hash": prev, "payload": payload, "block_hash": block_hash}
        with open(self.path, "ab") as f:
            f.write(canonical(block) + b"\n")
        return block

    def verify(self) -> bool:
        blocks = self._read_blocks()
        prev = sha256(b"GENESIS")
        for b in blocks:
            exp = sha256(prev.encode() + canonical(b["payload"]))
            if b["prev_hash"] != prev:
                return False
            if b["block_hash"] != exp:
                return False
            prev = b["block_hash"]
        return True

    def find_by(self, key: str, value: str) -> List[Dict[str, Any]]:
        blocks = self._read_blocks()
        out = []
        for b in blocks:
            p = b["payload"]
            if isinstance(p, dict) and p.get(key) == value:
                out.append(b)
        return out

    def all_payloads(self) -> List[Dict[str, Any]]:
        return [b["payload"] for b in self._read_blocks()]
