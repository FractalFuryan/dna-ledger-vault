from __future__ import annotations
import os
from typing import Tuple
from .crypto import seal_bytes, open_bytes

class Vault:
    def __init__(self, dirpath: str):
        self.dirpath = dirpath
        os.makedirs(dirpath, exist_ok=True)

    def put(self, name: str, key: bytes, plaintext: bytes, aad: bytes) -> str:
        blob = seal_bytes(key, plaintext, aad)
        path = os.path.join(self.dirpath, f"{name}.sealed")
        with open(path, "wb") as f:
            f.write(blob)
        return path

    def get(self, name: str, key: bytes, aad: bytes) -> bytes:
        path = os.path.join(self.dirpath, f"{name}.sealed")
        with open(path, "rb") as f:
            blob = f.read()
        return open_bytes(key, blob, aad)
