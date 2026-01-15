#!/usr/bin/env bash
# Quick status check for DNA Ledger Vault
# Shows: ethics anchor, test status, dependencies, docs

set -e

echo "🧬 DNA Ledger Vault - Quick Status"
echo "=================================="
echo ""

# Ethics anchor
ETHICS_ANCHOR="65b14d584f5a5fd070fe985eeb86e14cb3ce56a4fc41fd9e987f2259fe1f15c1"
echo "🔒 Ethics Anchor: $ETHICS_ANCHOR"

if grep -q "$ETHICS_ANCHOR" docs/SECURITY.md; then
    echo "   ✅ Verified in SECURITY.md"
else
    echo "   ❌ NOT FOUND in SECURITY.md"
fi
echo ""

# Test status
echo "🧪 Test Status:"
if command -v pytest &> /dev/null; then
    if pytest --collect-only -q 2>&1 | grep -q "test"; then
        TEST_COUNT=$(pytest --collect-only -q 2>&1 | grep -c "test_" || true)
        echo "   📊 $TEST_COUNT tests collected"
    fi
else
    echo "   ⚠️  pytest not installed"
fi
echo ""

# Dependencies
echo "📦 Dependencies:"
if [ -f "requirements.txt" ] && [ -f "requirements-lock.txt" ]; then
    REQ_COUNT=$(wc -l < requirements.txt)
    LOCK_COUNT=$(wc -l < requirements-lock.txt)
    echo "   ✅ requirements.txt ($REQ_COUNT lines)"
    echo "   ✅ requirements-lock.txt ($LOCK_COUNT lines, frozen)"
else
    echo "   ❌ Missing dependency files"
fi
echo ""

# Documentation
echo "📚 Documentation:"
DOC_COUNT=$(find docs -name "*.md" -type f | wc -l)
echo "   📄 $DOC_COUNT markdown files in docs/"

REQUIRED_DOCS=(
    "docs/SECURITY.md"
    "docs/AUDIT.md"
    "docs/GLOSSARY.md"
    "docs/ETHICS-PROBABILISTIC-DISTANCE.md"
)

for doc in "${REQUIRED_DOCS[@]}"; do
    if [ -f "$doc" ]; then
        echo "   ✅ $(basename $doc)"
    else
        echo "   ❌ $(basename $doc) MISSING"
    fi
done
echo ""

# Schema version
if [ -f "dna_ledger/__init__.py" ]; then
    VERSION=$(grep "__version__" dna_ledger/__init__.py | cut -d'"' -f2)
    SCHEMA=$(grep "__schema__" dna_ledger/__init__.py | cut -d'"' -f2)
    echo "🏷️  Version: $VERSION"
    echo "🏷️  Schema:  $SCHEMA"
else
    echo "⚠️  Version info not found"
fi
echo ""

# Ledger status
if [ -f "state/ledger.jsonl" ]; then
    BLOCK_COUNT=$(wc -l < state/ledger.jsonl)
    echo "⛓️  Ledger: $BLOCK_COUNT blocks in state/ledger.jsonl"
else
    echo "⛓️  Ledger: Not initialized"
fi
echo ""

echo "=================================="
echo "✅ Status check complete"
