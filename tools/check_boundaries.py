"""
Boundary Gate - Enforce Math vs Interpretation Separation

This tool verifies that critical boundary documentation exists and contains
required disclaimers to prevent "bleed-through" between mathematical substrate
and interpretive framework.

Usage:
    python tools/check_boundaries.py

Exit codes:
    0 - All boundaries intact
    1 - Missing files or required snippets

Enforced via CI: .github/workflows/boundary_gate.yml
"""

from __future__ import annotations

import sys
from pathlib import Path

# Files that MUST exist to enforce the boundary
REQUIRED_FILES = [
    "docs/SCALAR_WAZE_BOUNDARY.md",
    "docs/NON_CLAIMS.md",
    "docs/CLAIMS_REGISTER.md",
]

# Critical phrases that MUST appear in each file (anti-drift protection)
REQUIRED_SNIPPETS = {
    "docs/SCALAR_WAZE_BOUNDARY.md": [
        "Mathematical Substrate Notice",
        "modify, extend, or claim ownership",
        "Scalar Waze stops at",
        "Explicit Exclusions",
        "NOT a physical theory",
        "NOT a proof strategy",
        "Boundary Rule",
        "Conditional",
    ],
    "docs/NON_CLAIMS.md": [
        "This work does not claim",
        "Riemann Hypothesis",
        "physical realization",
        "Hard Boundary",
    ],
    "docs/CLAIMS_REGISTER.md": [
        "Grounded (Mathematics)",
        "Interpretive / Constraint-Layer",
        "Engineering",
        "No layer depends on belief in the layer above it",
    ],
}


def fail(msg: str) -> int:
    """Print error message and return failure code."""
    print(f"❌ boundary gate: {msg}", file=sys.stderr)
    return 1


def main() -> int:
    """Run boundary verification checks."""
    # Find repo root (one level up from tools/)
    repo = Path(__file__).resolve().parents[1]

    # Check for missing files
    missing = [p for p in REQUIRED_FILES if not (repo / p).exists()]
    if missing:
        return fail(f"missing required docs: {missing}")

    # Check for missing snippets in each file
    for rel_path, snippets in REQUIRED_SNIPPETS.items():
        full_path = repo / rel_path
        try:
            text = full_path.read_text(encoding="utf-8", errors="replace")
            # Remove markdown formatting for more flexible matching
            text_normalized = text.replace("**", "").replace("*", "")
        except Exception as e:
            return fail(f"failed to read {rel_path!r}: {e}")

        for snippet in snippets:
            if snippet not in text_normalized:
                return fail(f"missing snippet in {rel_path!r}: {snippet!r}")

    # All checks passed
    print("✅ boundary gate: OK")
    print("   - All required files present")
    print("   - All critical snippets verified")
    print("   - Math/interpretation boundary enforced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
