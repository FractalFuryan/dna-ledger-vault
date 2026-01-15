#!/usr/bin/env bash
# Documentation verification script
# Ensures all required docs exist and are linked properly

set -e

echo "🔍 DNA Ledger Vault - Documentation Verification"
echo "================================================"
echo ""

REQUIRED_DOCS=(
    "README.md"
    "docs/SECURITY.md"
    "docs/AUDIT.md"
    "docs/CRYPTO_UPGRADES.md"
    "docs/GLOSSARY.md"
    "docs/THREAD-2026-01-15.md"
    "docs/ETHICS-PROBABILISTIC-DISTANCE.md"
    "docs/GEO-PHASE.md"
    "docs/STATE-MIXER-FK.md"
    "docs/ZK-TELEPORT-OPTION-A.md"
    "docs/ENGINEERING-TODO-2026-01-15.md"
)

ETHICS_ANCHOR="65b14d584f5a5fd070fe985eeb86e14cb3ce56a4fc41fd9e987f2259fe1f15c1"

# Check required docs exist
echo "📄 Checking required documentation files..."
MISSING_DOCS=0
for doc in "${REQUIRED_DOCS[@]}"; do
    if [ ! -f "$doc" ]; then
        echo "   ❌ Missing: $doc"
        MISSING_DOCS=$((MISSING_DOCS + 1))
    else
        echo "   ✅ Found: $doc"
    fi
done

if [ $MISSING_DOCS -gt 0 ]; then
    echo ""
    echo "❌ $MISSING_DOCS required documentation file(s) missing"
    exit 1
fi

echo ""
echo "✅ All required documentation files present"
echo ""

# Check ethics anchor in SECURITY.md
echo "🔒 Verifying ethics anchor in SECURITY.md..."
if grep -q "$ETHICS_ANCHOR" docs/SECURITY.md; then
    echo "   ✅ Ethics anchor found in SECURITY.md"
else
    echo "   ❌ Ethics anchor NOT found in SECURITY.md"
    exit 1
fi

# Check ethics anchor in ETHICS-PROBABILISTIC-DISTANCE.md (optional, as it's not the hash itself)
echo ""

# Check cross-references
echo "🔗 Checking documentation cross-references..."
XREF_ERRORS=0

# README should reference thread archive
if grep -q "THREAD-2026-01-15.md" README.md; then
    echo "   ✅ README.md references THREAD-2026-01-15.md"
else
    echo "   ❌ README.md missing thread archive reference"
    XREF_ERRORS=$((XREF_ERRORS + 1))
fi

# SECURITY.md should reference ETHICS-PROBABILISTIC-DISTANCE.md
if grep -q "ETHICS-PROBABILISTIC-DISTANCE.md" docs/SECURITY.md; then
    echo "   ✅ SECURITY.md references ETHICS-PROBABILISTIC-DISTANCE.md"
else
    echo "   ❌ SECURITY.md missing ethics doctrine reference"
    XREF_ERRORS=$((XREF_ERRORS + 1))
fi

# GEO-PHASE.md should have runtime gating section
if grep -q "Why No Runtime Cosine Gating" docs/GEO-PHASE.md; then
    echo "   ✅ GEO-PHASE.md contains runtime gating rationale"
else
    echo "   ❌ GEO-PHASE.md missing runtime gating rationale"
    XREF_ERRORS=$((XREF_ERRORS + 1))
fi

# GLOSSARY.md should define procedural vs likeness personalization
if grep -qi "Procedural [Pp]ersonalization" docs/GLOSSARY.md && grep -qi "Likeness [Pp]ersonalization" docs/GLOSSARY.md; then
    echo "   ✅ GLOSSARY.md defines personalization types"
else
    echo "   ❌ GLOSSARY.md missing personalization definitions"
    XREF_ERRORS=$((XREF_ERRORS + 1))
fi

echo ""
if [ $XREF_ERRORS -gt 0 ]; then
    echo "❌ $XREF_ERRORS cross-reference error(s) found"
    exit 1
else
    echo "✅ All cross-references valid"
fi

echo ""
echo "================================================"
echo "✅ Documentation verification PASSED"
echo "================================================"
