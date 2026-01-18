"""
Test fail-closed gate behavior.

Verifies:
- Missing geoCommit blocks request
- Revoked commitments block request
- Chain unreachable blocks request (STRICT_CHAIN=true)
- Revocation check failure blocks request (STRICT_REVOCATION=true)
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from geophase_eth.eth.middleware import build_geocommit_gate
from geophase_eth.eth.settings import Settings


class FakeMetrics:
    """Mock metrics for testing."""

    def inc(self, *_args, **_kwargs):
        pass

    def observe(self, *_args, **_kwargs):
        pass


class FakeClient:
    """Mock chain client for testing."""

    def __init__(
        self, *, ping_ok=True, revoked=False, raise_on_revocation=False
    ):
        self._ping_ok = ping_ok
        self._revoked = revoked
        self._raise = raise_on_revocation
        self.metrics = FakeMetrics()

    def bytecode_lock(self, *_args, **_kwargs):
        return None

    def ping(self):
        return self._ping_ok

    def is_revoked(self, _geo_commit: bytes):
        if self._raise:
            raise RuntimeError("rpc fail")
        return self._revoked


@dataclass
class FakeReq:
    """Mock FastAPI request."""

    query_params: dict


def _base_settings(**overrides):
    """Create base test settings."""
    defaults = dict(
        BASE_RPC_URL="https://test.example",
        ATTESTATION_REGISTRY_ADDR="0x" + "11" * 20,
        REVOCATION_REGISTRY_ADDR="0x" + "22" * 20,
        STRICT_CHAIN=True,
        STRICT_REVOCATION=True,
        BYTECODE_LOCK_ENABLED=False,
        ATTESTATION_CODEHASH="",
        REVOCATION_CODEHASH="",
        ATTEST_ENABLED=False,
    )
    defaults.update(overrides)
    return Settings(**defaults)


def test_gate_blocks_missing_geocommit():
    """Gate blocks requests without geoCommit parameter."""
    s = _base_settings()
    gate = build_geocommit_gate(s, FakeClient())
    res = gate(FakeReq(query_params={}))

    assert not res.allowed
    assert res.reason == "MISSING_GEO_COMMIT"


def test_gate_blocks_invalid_geocommit():
    """Gate blocks requests with invalid geoCommit format."""
    s = _base_settings()
    gate = build_geocommit_gate(s, FakeClient())

    # Not hex
    res = gate(FakeReq(query_params={"geoCommit": "not-hex"}))
    assert not res.allowed
    assert res.reason == "INVALID_GEO_COMMIT"

    # Wrong length
    res = gate(FakeReq(query_params={"geoCommit": "0x" + "11" * 16}))
    assert not res.allowed
    assert res.reason == "INVALID_GEO_COMMIT"


def test_gate_blocks_when_revoked():
    """Gate blocks requests for revoked commitments."""
    s = _base_settings()
    gate = build_geocommit_gate(s, FakeClient(revoked=True))
    res = gate(FakeReq(query_params={"geoCommit": "0x" + "11" * 32}))

    assert not res.allowed
    assert res.reason == "REVOKED"


def test_gate_fail_closed_when_chain_down_strict():
    """Gate raises at startup when chain down and STRICT_CHAIN=true."""
    s = _base_settings(STRICT_CHAIN=True)
    
    # Should raise at gate construction time, not request time
    with pytest.raises(RuntimeError, match="Chain unreachable at startup"):
        build_geocommit_gate(s, FakeClient(ping_ok=False))


def test_gate_soft_fail_when_chain_down_lenient():
    """Gate allows when chain down and STRICT_CHAIN=false."""
    s = _base_settings(STRICT_CHAIN=False)
    gate = build_geocommit_gate(s, FakeClient(ping_ok=False, revoked=False))
    res = gate(FakeReq(query_params={"geoCommit": "0x" + "11" * 32}))

    assert res.allowed
    assert res.reason == "CHAIN_SOFTFAIL"


def test_gate_fail_closed_when_revocation_check_fails_strict():
    """Gate blocks when revocation check fails and STRICT_REVOCATION=true."""
    s = _base_settings(STRICT_REVOCATION=True)
    gate = build_geocommit_gate(s, FakeClient(raise_on_revocation=True))
    res = gate(FakeReq(query_params={"geoCommit": "0x" + "11" * 32}))

    assert not res.allowed
    assert res.reason == "REVOCATION_CHECK_FAILED"


def test_gate_soft_fail_when_revocation_check_fails_lenient():
    """Gate allows when revocation check fails and STRICT_REVOCATION=false."""
    s = _base_settings(STRICT_REVOCATION=False)
    gate = build_geocommit_gate(s, FakeClient(raise_on_revocation=True))
    res = gate(FakeReq(query_params={"geoCommit": "0x" + "11" * 32}))

    assert res.allowed
    assert res.reason == "REVOCATION_SOFTFAIL"


def test_gate_allows_valid_non_revoked():
    """Gate allows valid, non-revoked commitment."""
    s = _base_settings()
    gate = build_geocommit_gate(s, FakeClient(revoked=False))
    res = gate(FakeReq(query_params={"geoCommit": "0x" + "aa" * 32}))

    assert res.allowed
    assert res.reason == "OK"
