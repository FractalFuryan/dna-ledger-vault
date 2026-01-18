"""
Phase 2 Security Invariant Tests
Lock down onboarding, dashboard, and compliance artifact safety.
"""

import json
import subprocess
import tempfile
from pathlib import Path

import pytest

from dna_ledger.ledger import HashChainedLedger
from dna_ledger.models import DatasetCommit, ConsentGrant
from onboarding.wizard import OnboardingWizard
from onboarding.compliance_templates import ComplianceTemplates


class TestOnboardingInvariants:
    """Ensure onboarding wizard does not bypass consent logic."""
    
    def test_onboarding_uses_cli_only(self, tmp_path, monkeypatch):
        """
        CRITICAL: Wizard must never write ledger directly.
        All mutations flow through existing CLI commands.
        """
        # Track all file writes during wizard execution
        write_calls = []
        original_write_text = Path.write_text
        
        def monitored_write_text(self, *args, **kwargs):
            write_calls.append(str(self))
            return original_write_text(self, *args, **kwargs)
        
        monkeypatch.setattr(Path, "write_text", monitored_write_text)
        
        # Create minimal wizard (doesn't run full flow, just checks structure)
        wizard = OnboardingWizard(output_dir=str(tmp_path))
        
        # Verify wizard never imports ledger writing code
        import inspect
        wizard_source = inspect.getsource(OnboardingWizard)
        
        # Assert no direct ledger manipulation
        assert "HashChainedLedger" not in wizard_source
        assert "append_event" not in wizard_source
        assert ".write(" not in wizard_source  # No raw file writes
        
        # Assert only subprocess calls to CLI
        assert "subprocess" in wizard_source
        assert "cli.main" in wizard_source
    
    def test_onboarding_no_ledger_state_mutation(self):
        """Wizard generates artifacts but never modifies ledger state."""
        # Verify wizard module never imports ledger manipulation code
        import inspect
        import onboarding.wizard as wizard_module
        
        wizard_source = inspect.getsource(wizard_module)
        
        # Assert no direct ledger manipulation
        assert "from dna_ledger.ledger import" not in wizard_source
        assert "HashChainedLedger" not in wizard_source
        assert ".append(" not in wizard_source  # Ledger append method
        
        # Wizard should only use CLI subprocess calls
        assert "subprocess.run" in wizard_source


class TestDashboardReadOnly:
    """Ensure dashboard endpoints have no mutating routes."""
    
    def test_dashboard_has_no_mutating_routes(self):
        """
        CRITICAL: Dashboard must be strictly read-only.
        No POST/PUT/DELETE/PATCH endpoints allowed.
        """
        from api.server import app
        
        # Introspect all Flask routes
        routes = []
        for rule in app.url_map.iter_rules():
            routes.append({
                "endpoint": rule.endpoint,
                "methods": rule.methods,
                "rule": rule.rule
            })
        
        # Check v1 API routes
        mutating_routes = []
        for route in routes:
            # Exclude OPTIONS (CORS), HEAD (standard)
            methods = route["methods"] - {"OPTIONS", "HEAD"}
            
            # Exclude GA4GH passport POST (separate Phase 1 feature, not dashboard)
            if "/passports/issue" in route["rule"]:
                continue
            
            # Flag any non-GET methods
            if methods != {"GET"}:
                mutating_routes.append(route)
        
        # Dashboard v1 should have NO mutating routes
        # (All operations are read-only views of ledger state)
        assert len(mutating_routes) == 0, f"Found mutating routes: {mutating_routes}"
    
    def test_dashboard_v2_read_only(self):
        """FastAPI v2 observability API must also be read-only."""
        from api.v2.observability import app
        
        # Introspect FastAPI routes
        routes = []
        for route in app.routes:
            if hasattr(route, "methods"):
                routes.append({
                    "path": route.path,
                    "methods": route.methods,
                    "name": route.name
                })
        
        # Check for mutating methods
        mutating_routes = []
        for route in routes:
            # Exclude OpenAPI/Swagger documentation routes (GET/HEAD only)
            if route["path"] in ["/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"]:
                continue
            
            # Exclude HEAD method (standard)
            methods = route["methods"] - {"HEAD"}
            
            # FastAPI routes should only be GET
            if methods != {"GET"}:
                mutating_routes.append(route)
        
        # v2 Observability API must be strictly read-only
        assert len(mutating_routes) == 0, f"Found mutating routes in v2: {mutating_routes}"
    
    def test_dashboard_no_crypto_operations(self):
        """Dashboard must not initiate signing, encryption, or key generation."""
        # Check v1 API server
        import api.server as server_module
        import inspect
        
        server_source = inspect.getsource(server_module)
        
        # Assert no cryptographic operations
        forbidden_operations = [
            "gen_ed25519",
            "sign_payload",
            "new_key",
            "encrypt(",
            "wrap_dek",
            "rotate_key"
        ]
        
        for operation in forbidden_operations:
            assert operation not in server_source, \
                f"Dashboard v1 contains forbidden operation: {operation}"
        
        # Check v2 API server
        import api.v2.observability as obs_module
        obs_source = inspect.getsource(obs_module)
        
        for operation in forbidden_operations:
            assert operation not in obs_source, \
                f"Dashboard v2 contains forbidden operation: {operation}"


class TestComplianceArtifacts:
    """Ensure compliance documents are deterministic and reproducible."""
    
    def test_compliance_package_reproducible(self, tmp_path):
        """
        CRITICAL: Same inputs must produce identical compliance artifacts.
        This ensures regulatory submissions are deterministic.
        """
        org_info = {
            "org_name": "Test Hospital",
            "org_type": "Hospital",
            "jurisdiction": "EU",
            "dpo_email": "dpo@test.org"
        }
        
        # Generate DPA twice
        dpa1 = ComplianceTemplates.generate_dpa_template(org_info)
        dpa2 = ComplianceTemplates.generate_dpa_template(org_info)
        
        # Strip timestamps (which are expected to differ)
        import re
        dpa1_stripped = re.sub(r"Generated: \d{4}-\d{2}-\d{2}", "Generated: TIMESTAMP", dpa1)
        dpa2_stripped = re.sub(r"Generated: \d{4}-\d{2}-\d{2}", "Generated: TIMESTAMP", dpa2)
        
        # Assert determinism (except for timestamps)
        assert dpa1_stripped == dpa2_stripped
    
    def test_dpia_has_required_sections(self):
        """DPIA must include all GDPR Article 35 required elements."""
        dataset_info = {
            "id": "ds_test",
            "metadata": {
                "dataset_name": "Test Dataset",
                "data_type": "Genomic Variants (VCF)"
            }
        }
        
        dpia = ComplianceTemplates.generate_dpia_outline(dataset_info)
        
        # GDPR Article 35 requirements
        required_sections = [
            "NECESSITY AND PROPORTIONALITY",
            "RISKS TO DATA SUBJECTS",
            "MEASURES TO ADDRESS RISKS",
            "CONSULTATION AND SIGN-OFF",
            "MONITORING AND REVIEW"
        ]
        
        for section in required_sections:
            assert section in dpia, f"DPIA missing required section: {section}"
    
    def test_compliance_checklist_covers_gdpr_cpra(self):
        """Checklist must cover both GDPR and CPRA requirements."""
        checklist = ComplianceTemplates.generate_compliance_checklist()
        
        # Must include GDPR articles
        assert "GDPR Art. 17" in checklist  # Right to Erasure
        assert "GDPR Art. 32" in checklist  # Security
        assert "GDPR Art. 30" in checklist  # Records of Processing
        
        # Must include CPRA sections
        assert "CPRA §1798.100" in checklist  # Right to know
        assert "CPRA §1798.105" in checklist  # Right to delete
        
        # Must reference implemented features
        assert "ChaCha20-Poly1305" in checklist
        assert "DoD 5220.22-M" in checklist
        assert "SHA256" in checklist  # Hash chain integrity
    
    def test_compliance_artifacts_no_execution_risk(self):
        """Templates must be safe (no code execution, no SQL, no scripts)."""
        org_info = {"org_name": "'; DROP TABLE--", "org_type": "Test", "jurisdiction": "EU", "dpo_email": "test@test"}
        
        # Generate with injection attempt
        dpa = ComplianceTemplates.generate_dpa_template(org_info)
        
        # Assert no code execution markers
        assert "<script>" not in dpa
        assert "<?php" not in dpa
        assert "eval(" not in dpa
        assert "exec(" not in dpa
        
        # Assert input is sanitized/escaped in output
        assert "'; DROP TABLE--" in dpa  # Should be literal text, not executed


class TestOnboardingCLIIntegration:
    """Ensure CLI integration is properly namespaced."""
    
    def test_onboarding_command_namespaced(self):
        """Onboarding commands must be under 'onboarding' namespace."""
        import cli.main as main_module
        import inspect
        
        main_source = inspect.getsource(main_module)
        
        # Assert onboarding is explicitly scoped
        assert 'sub.add_parser("onboarding"' in main_source
        assert "onboarding_cmd" in main_source  # Subparser dest
        
        # Assert individual commands are under the namespace
        assert "onboarding wizard" in main_source.lower()
        assert "onboarding generate-dpa" in main_source.lower()
        assert "onboarding generate-dpia" in main_source.lower()
        assert "onboarding generate-checklist" in main_source.lower()
    
    def test_onboarding_cli_help_output(self, tmp_path):
        """CLI help should show namespaced onboarding commands."""
        result = subprocess.run(
            ["python", "-m", "cli.main", "onboarding", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        
        assert result.returncode == 0
        help_output = result.stdout
        
        # Should list all onboarding subcommands
        assert "wizard" in help_output
        assert "generate-dpa" in help_output
        assert "generate-dpia" in help_output
        assert "generate-checklist" in help_output
