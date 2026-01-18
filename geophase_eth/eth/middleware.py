"""
Fail-closed FastAPI middleware for GeoPhase generation gating.

Pre-generation checks:
1. Bytecode lock (optional, recommended in production)
2. RPC reachability (STRICT_CHAIN)
3. Revocation check (STRICT_REVOCATION)

Fails closed on any check failure when strict mode enabled.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fastapi import HTTPException, Request

from geophase_eth.eth.chain_client import ChainClient
from geophase_eth.eth.settings import Settings


@dataclass(frozen=True)
class GateResult:
    """Result of pre-generation gate check."""

    allowed: bool
    reason: str = ""


def _hex32_to_bytes(h: str) -> bytes:
    """
    Convert 0x-prefixed 32-byte hex string to bytes.
    
    Raises:
        ValueError: If invalid format or length
    """
    if not h.startswith("0x"):
        raise ValueError("geoCommit must be 0x-prefixed")
    b = bytes.fromhex(h[2:])
    if len(b) != 32:
        raise ValueError("geoCommit must be 32 bytes")
    return b


def build_geocommit_gate(
    settings: Settings, client: ChainClient
) -> Callable[[Request], GateResult]:
    """
    Build pre-generation gate function.
    
    Performs startup checks:
    - Bytecode lock verification (if enabled)
    - Chain reachability (if STRICT_CHAIN)
    
    Returns gate function that checks:
    - geoCommit parameter presence and format
    - RPC health (if STRICT_CHAIN)
    - Revocation status (if STRICT_REVOCATION)
    
    Args:
        settings: Server configuration
        client: Chain client instance
    
    Returns:
        Gate function taking Request and returning GateResult
    
    Raises:
        RuntimeError: If startup checks fail
    """
    # Startup bytecode lock
    if settings.BYTECODE_LOCK_ENABLED:
        if not settings.ATTESTATION_CODEHASH or not settings.REVOCATION_CODEHASH:
            raise RuntimeError(
                "BYTECODE_LOCK_ENABLED but codehash env vars missing"
            )
        client.bytecode_lock(
            settings.ATTESTATION_CODEHASH, settings.REVOCATION_CODEHASH
        )

    # Startup chain health
    if settings.STRICT_CHAIN and not client.ping():
        raise RuntimeError("Chain unreachable at startup (STRICT_CHAIN=true)")

    def gate(req: Request) -> GateResult:
        """
        Per-request gate check.
        
        Args:
            req: FastAPI request with ?geoCommit=0x... query param
        
        Returns:
            GateResult indicating allow/deny + reason
        """
        # Expect geoCommit passed explicitly (commitment-only)
        geo_commit_hex = req.query_params.get("geoCommit")
        if not geo_commit_hex:
            return GateResult(False, "MISSING_GEO_COMMIT")

        try:
            geo_commit = _hex32_to_bytes(geo_commit_hex)
        except Exception:
            return GateResult(False, "INVALID_GEO_COMMIT")

        # Chain health check
        if not client.ping():
            if settings.STRICT_CHAIN:
                return GateResult(False, "CHAIN_UNREACHABLE")
            return GateResult(True, "CHAIN_SOFTFAIL")

        # Revocation check
        try:
            revoked = client.is_revoked(geo_commit)
        except Exception:
            if settings.STRICT_REVOCATION:
                return GateResult(False, "REVOCATION_CHECK_FAILED")
            return GateResult(True, "REVOCATION_SOFTFAIL")

        if revoked:
            client.metrics.inc("revocations_blocked_total")
            return GateResult(False, "REVOKED")

        client.metrics.inc("requests_allowed_total")
        return GateResult(True, "OK")

    return gate


async def enforce_gate(req: Request, gate: Callable[[Request], GateResult]) -> None:
    """
    Enforce gate check as FastAPI dependency.
    
    Args:
        req: FastAPI request
        gate: Gate function from build_geocommit_gate
    
    Raises:
        HTTPException: 403 if gate check fails
    """
    res = gate(req)
    if not res.allowed:
        raise HTTPException(status_code=403, detail=res.reason)
