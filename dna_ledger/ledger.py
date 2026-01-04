from __future__ import annotations
import json, os
from typing import Any, Dict, List, Optional
from .hashing import sha256
from .signing import verify_payload, canonical

class HashChainedLedger:
    """
    vNext:
    - Hash-chained blocks (tamper evident)
    - Each payload is Ed25519-signed (provenance)
    Block schema:
      {
        "prev_hash": "...",
        "payload": {...},
        "signer": {"id": "dave", "ed25519_pub_pem_b64": "..."},
        "sig": "<b64>",
        "block_hash": "..."
      }
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

    def append(self, payload: Dict[str, Any], signer: Dict[str, str], sig_b64: str) -> Dict[str, Any]:
        prev = self.tip_hash()
        block_hash = sha256(prev.encode() + canonical(payload))
        block = {
            "prev_hash": prev,
            "payload": payload,
            "signer": signer,
            "sig": sig_b64,
            "block_hash": block_hash
        }
        with open(self.path, "ab") as f:
            f.write(json.dumps(block, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
        return block

    def verify(self) -> bool:
        blocks = self._read_blocks()
        prev = sha256(b"GENESIS")
        for b in blocks:
            payload = b["payload"]
            # chain integrity
            exp_hash = sha256(prev.encode() + canonical(payload))
            if b["prev_hash"] != prev:
                return False
            if b["block_hash"] != exp_hash:
                return False
            # signature integrity
            pub_b64 = b["signer"]["ed25519_pub_pem_b64"]
            pub_pem = __import__("base64").b64decode(pub_b64.encode("utf-8"))
            if not verify_payload(pub_pem, payload, b["sig"]):
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
