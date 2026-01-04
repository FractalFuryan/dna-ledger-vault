from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from dna_ledger import MIN_SCHEMA_VERSION, SUPPORTED_SCHEMAS

from .hashing import h_block
from .signing import verify_payload


class SchemaDowngradeError(Exception):
    """Raised when a payload has an unsupported or older schema."""
    pass

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
        return blocks[-1]["block_hash"] if blocks else h_block({"genesis": True})

    def append(self, payload: Dict[str, Any], signer: Dict[str, str], sig_b64: str) -> Dict[str, Any]:
        # Schema validation: prevent downgrade attacks
        schema = payload.get("schema")
        if schema and schema not in SUPPORTED_SCHEMAS:
            raise SchemaDowngradeError(
                f"Unsupported schema '{schema}'. Supported: {SUPPORTED_SCHEMAS}"
            )
        if schema and schema < MIN_SCHEMA_VERSION:
            raise SchemaDowngradeError(
                f"Schema '{schema}' older than minimum required '{MIN_SCHEMA_VERSION}'"
            )
        
        prev = self.tip_hash()
        # Block hash covers full header: prev + payload + signer + sig
        block_header = {
            "prev_hash": prev,
            "payload": payload,
            "signer": signer,
            "sig": sig_b64
        }
        block_hash = h_block(block_header)
        block = {**block_header, "block_hash": block_hash}
        with open(self.path, "ab") as f:
            f.write(json.dumps(block, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
        return block

    def verify(self) -> bool:
        blocks = self._read_blocks()
        prev = h_block({"genesis": True})
        for b in blocks:
            payload = b["payload"]
            signer = b["signer"]
            sig = b["sig"]
            
            # Chain integrity: check block hash covers full header
            block_header = {
                "prev_hash": prev,
                "payload": payload,
                "signer": signer,
                "sig": sig
            }
            exp_hash = h_block(block_header)
            if b["prev_hash"] != prev:
                return False
            if b["block_hash"] != exp_hash:
                return False
            
            # Signature integrity
            pub_b64 = signer["ed25519_pub_pem_b64"]
            pub_pem = __import__("base64").b64decode(pub_b64.encode("utf-8"))
            if not verify_payload(pub_pem, payload, sig):
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
