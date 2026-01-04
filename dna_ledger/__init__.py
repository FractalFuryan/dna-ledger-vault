"""
DNA Ledger Vault - Cryptographically-verified genomic data ledger.

Schema Version: dna-ledger-vault/vNext.2
Security Invariants: SECURITY.md#invariants
"""

__version__ = "0.2.0"
__schema__ = "dna-ledger-vault/vNext.2"
__invariants__ = "SECURITY.md#invariants"

# Supported schema versions (for backward compatibility)
SUPPORTED_SCHEMAS = [
    "dna-ledger-vault/vNext.2",
    # Add older versions here if needed for migration
]

# Minimum required schema for new entries
MIN_SCHEMA_VERSION = "dna-ledger-vault/vNext.2"
