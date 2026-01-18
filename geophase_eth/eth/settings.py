"""
Server configuration with fail-closed defaults.

Environment variables control behavior:
- STRICT_CHAIN: Fail if RPC unreachable (default: true)
- STRICT_REVOCATION: Fail if revocation check fails (default: true)
- BYTECODE_LOCK_ENABLED: Verify contract bytecode hash (default: true)
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _req(name: str) -> str:
    """Get required environment variable or raise."""
    v = os.getenv(name)
    if not v:
        raise RuntimeError(f"Missing required env var: {name}")
    return v


def _opt(name: str, default: str) -> str:
    """Get optional environment variable with default."""
    return os.getenv(name, default)


def _opt_bool(name: str, default: bool) -> bool:
    """Parse boolean environment variable."""
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


@dataclass(frozen=True)
class Settings:
    """Server configuration for Ethereum bridge."""

    BASE_RPC_URL: str
    ATTESTATION_REGISTRY_ADDR: str
    REVOCATION_REGISTRY_ADDR: str

    # Fail-closed behaviors (default: strict)
    STRICT_CHAIN: bool = True
    STRICT_REVOCATION: bool = True

    # Bytecode lock (recommended ON in production)
    BYTECODE_LOCK_ENABLED: bool = True
    ATTESTATION_CODEHASH: str = ""
    REVOCATION_CODEHASH: str = ""

    # Optional features
    ATTEST_ENABLED: bool = False

    @staticmethod
    def load() -> Settings:
        """Load settings from environment variables."""
        return Settings(
            BASE_RPC_URL=_req("BASE_RPC_URL"),
            ATTESTATION_REGISTRY_ADDR=_req("ATTESTATION_REGISTRY_ADDR"),
            REVOCATION_REGISTRY_ADDR=_req("REVOCATION_REGISTRY_ADDR"),
            STRICT_CHAIN=_opt_bool("STRICT_CHAIN", True),
            STRICT_REVOCATION=_opt_bool("STRICT_REVOCATION", True),
            BYTECODE_LOCK_ENABLED=_opt_bool("BYTECODE_LOCK_ENABLED", True),
            ATTESTATION_CODEHASH=_opt("ATTESTATION_CODEHASH", ""),
            REVOCATION_CODEHASH=_opt("REVOCATION_CODEHASH", ""),
            ATTEST_ENABLED=_opt_bool("ATTEST_ENABLED", False),
        )
