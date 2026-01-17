.PHONY: help install install-foundry test verify clean format lint ethics status docs-verify contracts deploy-sepolia typecheck

help:
	@echo "DNA Ledger Vault - Makefile targets"
	@echo "===================================="
	@echo ""
	@echo "Setup:"
	@echo "  make install          - Install dependencies"
	@echo "  make install-foundry  - Install Foundry (Solidity toolchain)"
	@echo ""
	@echo "Testing:"
	@echo "  make test             - Run all tests"
	@echo "  make ethics           - Run ethics invariant tests"
	@echo "  make crypto           - Run crypto scheme tests"
	@echo ""
	@echo "Ethereum:"
	@echo "  make contracts        - Build Solidity contracts"
	@echo "  make deploy-sepolia   - Deploy to Base Sepolia testnet"
	@echo ""
	@echo "Verification:"
	@echo "  make verify       - Verify ledger integrity"
	@echo "  make docs-verify  - Verify documentation completeness"
	@echo "  make status       - Quick status check"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint         - Run ruff linter"
	@echo "  make format       - Format code with ruff"
	@echo "  make typecheck    - Run mypy type checking"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean        - Remove cache files"
	@echo ""

install:
	pip install -e .

test:
	pytest -v

ethics:
	pytest tests/test_invariants.py -v

crypto:
	pytest tests/test_crypto_schemes.py -v

verify:
	@if [ -f state/ledger.jsonl ]; then \
		python -m cli.main verify --out state; \
	else \
		echo "⚠️  No ledger found in state/"; \
	fi

docs-verify:
	./scripts/verify-docs.sh

status:
	./scripts/status.sh

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy .

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf out cache broadcast *.egg-info

install-foundry:
	@command -v forge >/dev/null 2>&1 || { \
		echo "Installing Foundry..."; \
		curl -L https://foundry.paradigm.xyz | bash; \
		foundryup; \
	}
	@echo "✅ Foundry installed"

contracts:
	forge build
	@echo "✅ Contracts compiled"

deploy-sepolia:
	python -m geophase_eth.deploy --network base-sepolia
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "✅ Cleaned cache files"
