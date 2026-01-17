"""
Deploy GeoPhase commitments to Ethereum/Base.

Usage:
    python -m geophase_eth.deploy --network base-sepolia
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from eth_account import Account
from web3 import Web3


def load_contract_artifact(name: str) -> dict:
    """Load compiled contract artifact from Foundry output."""
    artifact_path = Path(__file__).parent.parent / "out" / f"{name}.sol" / f"{name}.json"
    if not artifact_path.exists():
        raise FileNotFoundError(
            f"Contract artifact not found: {artifact_path}\n"
            "Run: forge build"
        )
    return json.loads(artifact_path.read_text())


def deploy_contracts(rpc_url: str, private_key: str) -> dict:
    """
    Deploy AnankeAttestationRegistry and AnankeRevocationRegistry.
    
    Args:
        rpc_url: Base RPC endpoint
        private_key: Deployer private key (hex string)
    
    Returns:
        Dict with deployed contract addresses
    """
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    assert w3.is_connected(), f"Failed to connect to RPC: {rpc_url}"

    account = Account.from_key(private_key)
    print(f"Deploying from: {account.address}")
    print(f"Balance: {w3.from_wei(w3.eth.get_balance(account.address), 'ether')} ETH")

    # Load contract artifacts
    attestation_artifact = load_contract_artifact("AnankeAttestationRegistry")
    revocation_artifact = load_contract_artifact("AnankeRevocationRegistry")

    # Deploy AttestationRegistry
    print("\nDeploying AnankeAttestationRegistry...")
    AttestationRegistry = w3.eth.contract(
        abi=attestation_artifact["abi"],
        bytecode=attestation_artifact["bytecode"]["object"],
    )
    
    tx_hash = AttestationRegistry.constructor().transact({"from": account.address})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    attestation_address = tx_receipt["contractAddress"]
    print(f"✅ AnankeAttestationRegistry: {attestation_address}")

    # Deploy RevocationRegistry
    print("\nDeploying AnankeRevocationRegistry...")
    RevocationRegistry = w3.eth.contract(
        abi=revocation_artifact["abi"],
        bytecode=revocation_artifact["bytecode"]["object"],
    )
    
    tx_hash = RevocationRegistry.constructor().transact({"from": account.address})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    revocation_address = tx_receipt["contractAddress"]
    print(f"✅ AnankeRevocationRegistry: {revocation_address}")

    return {
        "attestation": attestation_address,
        "revocation": revocation_address,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Deploy GeoPhase Ethereum contracts")
    parser.add_argument(
        "--network",
        choices=["base", "base-sepolia"],
        default="base-sepolia",
        help="Network to deploy to",
    )
    args = parser.parse_args()

    # Load environment
    from dotenv import load_dotenv
    load_dotenv()

    rpc_urls = {
        "base": os.getenv("BASE_RPC_URL", "https://mainnet.base.org"),
        "base-sepolia": os.getenv("BASE_SEPOLIA_RPC_URL", "https://sepolia.base.org"),
    }

    private_key = os.getenv("PRIVATE_KEY")
    if not private_key:
        raise ValueError("PRIVATE_KEY not set in environment")

    print(f"Deploying to: {args.network}")
    addresses = deploy_contracts(rpc_urls[args.network], private_key)

    print("\n" + "=" * 60)
    print("Deployment complete!")
    print("=" * 60)
    print(f"AnankeAttestationRegistry: {addresses['attestation']}")
    print(f"AnankeRevocationRegistry:  {addresses['revocation']}")
    print("\nUpdate .env with these addresses:")
    print(f"ATTESTATION_REGISTRY_ADDRESS={addresses['attestation']}")
    print(f"REVOCATION_REGISTRY_ADDRESS={addresses['revocation']}")
