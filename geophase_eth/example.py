"""
Example: GeoPhase commitment workflow with Ethereum attestation.
"""

from __future__ import annotations

import os

from geophase_eth import (
    ChainGate,
    compute_geo_commit,
    create_phase_hashes,
    create_seed_commit,
    sha256_hash,
)


def main() -> None:
    """Example workflow."""
    # 1. Create seed commitment
    seed = os.urandom(32)
    user_nonce = b"user_nonce_example_12345"
    seed_commit = create_seed_commit(seed, user_nonce)

    print("Seed commit:", seed_commit.hex())

    # 2. Create phase hashes (mock data for example)
    phase_a_vector = b"mock_phase_a_vector_data" * 10
    phase_b_vector = b"mock_phase_b_vector_data" * 10
    phase_a_hash, phase_b_hash = create_phase_hashes(phase_a_vector, phase_b_vector)

    print("Phase A hash:", phase_a_hash.hex())
    print("Phase B hash:", phase_b_hash.hex())

    # 3. Create policy commitment
    policy_doc = b"DNA_LEDGER_VAULT_POLICY_V1"
    policy_id = sha256_hash(policy_doc)

    print("Policy ID:", policy_id.hex())

    # 4. Compute GeoPhase commitment
    geo_commit = compute_geo_commit(
        seed_commit=seed_commit,
        phase_a_hash=phase_a_hash,
        phase_b_hash=phase_b_hash,
        policy_id=policy_id,
        version=1,
    )

    print("\nGeoPhase commitment:", geo_commit.hex())

    # 5. Check revocation before generation (if chain configured)
    rpc_url = os.getenv("BASE_SEPOLIA_RPC_URL", "https://sepolia.base.org")
    revocation_addr = os.getenv("REVOCATION_REGISTRY_ADDRESS")
    attestation_addr = os.getenv("ATTESTATION_REGISTRY_ADDRESS")

    if not revocation_addr:
        print("\nSkipping chain check (no REVOCATION_REGISTRY_ADDRESS in .env)")
        print("Deploy contracts first: python -m geophase_eth.deploy")
        return

    gate = ChainGate(
        rpc_url=rpc_url,
        revocation_address=revocation_addr,
        attestation_address=attestation_addr,
    )

    print("\nChecking revocation status...")
    try:
        gate.check_before_generation(geo_commit)
        print("✅ Not revoked - safe to generate")
    except ValueError as e:
        print(f"❌ {e}")
        return

    # 6. Check attestation status (if available)
    if attestation_addr:
        is_attested = gate.is_attested(geo_commit)
        print(f"Attestation status: {'✅ Attested' if is_attested else '⏳ Not yet attested'}")

        if is_attested:
            attestation = gate.get_attestation(geo_commit)
            print(f"  Ethics anchor: {attestation['ethicsAnchor'].hex()}")
            print(f"  Policy ID: {attestation['policyId'].hex()}")
            print(f"  Version: {attestation['version']}")
            print(f"  Attestor: {attestation['attestor']}")
            print(f"  Timestamp: {attestation['timestamp']}")

    print("\n✅ Workflow complete")


if __name__ == "__main__":
    main()
