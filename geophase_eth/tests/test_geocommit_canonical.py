"""
Test canonical GeoCommit computation.

Verifies:
- Deterministic hashing
- Domain separation
- Version locking
- Input validation
"""

from __future__ import annotations

import pytest

from geophase_eth.eth.geocommit import PREFIX_V1, compute_geo_commit_v1, to_hex32


def test_geocommit_length_and_prefix_stability():
    """Verify output is 32 bytes and prefix is stable."""
    seed_commit = b"\x11" * 32
    phaseA_hash = b"\x22" * 32
    phaseB_hash = b"\x33" * 32
    policy_id = b"\x44" * 32

    geo = compute_geo_commit_v1(
        seed_commit=seed_commit,
        phaseA_hash=phaseA_hash,
        phaseB_hash=phaseB_hash,
        policy_id=policy_id,
        version_u32=1,
    )

    assert isinstance(geo, (bytes, bytearray))
    assert len(geo) == 32
    assert PREFIX_V1 == b"ANANKE_GEO_COMMIT_V1"


def test_geocommit_deterministic():
    """Same inputs always produce same output."""
    base = dict(
        seed_commit=b"\x11" * 32,
        phaseA_hash=b"\x22" * 32,
        phaseB_hash=b"\x33" * 32,
        policy_id=b"\x44" * 32,
        version_u32=1,
    )

    g1 = compute_geo_commit_v1(**base)
    g2 = compute_geo_commit_v1(**base)

    assert g1 == g2


def test_geocommit_changes_on_any_input_flip():
    """Any input change produces different output."""
    base = dict(
        seed_commit=b"\x11" * 32,
        phaseA_hash=b"\x22" * 32,
        phaseB_hash=b"\x33" * 32,
        policy_id=b"\x44" * 32,
        version_u32=1,
    )

    g0 = compute_geo_commit_v1(**base)

    # Flip one byte in phaseA
    base["phaseA_hash"] = b"\x22" * 31 + b"\x23"
    g1 = compute_geo_commit_v1(**base)
    assert g0 != g1

    # Reset and flip version
    base["phaseA_hash"] = b"\x22" * 32
    base["version_u32"] = 2
    g2 = compute_geo_commit_v1(**base)
    assert g0 != g2


def test_geocommit_version_domain_separation():
    """Different versions produce different commitments."""
    base = dict(
        seed_commit=b"\xaa" * 32,
        phaseA_hash=b"\xbb" * 32,
        phaseB_hash=b"\xcc" * 32,
        policy_id=b"\xdd" * 32,
    )

    g_v1 = compute_geo_commit_v1(**base, version_u32=1)
    g_v2 = compute_geo_commit_v1(**base, version_u32=2)

    assert g_v1 != g_v2


def test_geocommit_rejects_wrong_length():
    """Reject non-32-byte inputs."""
    with pytest.raises(ValueError, match="32-byte"):
        compute_geo_commit_v1(
            seed_commit=b"\x11" * 31,  # Wrong length
            phaseA_hash=b"\x22" * 32,
            phaseB_hash=b"\x33" * 32,
            policy_id=b"\x44" * 32,
            version_u32=1,
        )


def test_geocommit_rejects_invalid_version():
    """Reject version outside uint32 range."""
    with pytest.raises(ValueError, match="out of range"):
        compute_geo_commit_v1(
            seed_commit=b"\x11" * 32,
            phaseA_hash=b"\x22" * 32,
            phaseB_hash=b"\x33" * 32,
            policy_id=b"\x44" * 32,
            version_u32=2**32,  # Out of range
        )


def test_to_hex32():
    """Verify hex conversion."""
    data = b"\x00" * 32
    hex_str = to_hex32(data)
    assert hex_str == "0x" + "00" * 32

    with pytest.raises(ValueError):
        to_hex32(b"\x00" * 31)  # Wrong length
