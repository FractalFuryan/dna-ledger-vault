#!/usr/bin/env python3
"""
Quick validation script for Phase 2 implementation.
Tests onboarding wizard, v2 observability API, and CLI integration.
"""

import subprocess
import sys
import time
from pathlib import Path


def run_command(cmd, check=True):
    """Run shell command and return output."""
    print(f"→ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result


def test_cli_integration():
    """Test CLI onboarding commands."""
    print("\n" + "="*70)
    print("TEST 1: CLI Integration")
    print("="*70)
    
    # Test help for onboarding command group
    result = run_command("python -m cli.main onboarding --help", check=False)
    if result.returncode != 0:
        print("✗ CLI onboarding command not available")
        return False
    
    print("✓ CLI onboarding command group available")
    
    # Test compliance checklist generation
    run_command("python -m cli.main onboarding generate-checklist --out /tmp/test_checklist.csv")
    if Path("/tmp/test_checklist.csv").exists():
        print("✓ Compliance checklist generated")
        with open("/tmp/test_checklist.csv") as f:
            lines = f.readlines()
            print(f"  {len(lines)} requirements tracked")
    else:
        print("✗ Checklist generation failed")
        return False
    
    # Test DPA generation
    run_command(
        'python -m cli.main onboarding generate-dpa '
        '--org-name "Test Hospital" '
        '--jurisdiction EU '
        '--out /tmp/test_dpa.md'
    )
    if Path("/tmp/test_dpa.md").exists():
        print("✓ DPA template generated")
    else:
        print("✗ DPA generation failed")
        return False
    
    # Test DPIA generation
    run_command(
        'python -m cli.main onboarding generate-dpia '
        '--dataset-name "Test Dataset" '
        '--dataset-id ds_test_001 '
        '--out /tmp/test_dpia.md'
    )
    if Path("/tmp/test_dpia.md").exists():
        print("✓ DPIA outline generated")
    else:
        print("✗ DPIA generation failed")
        return False
    
    return True


def test_v2_api_imports():
    """Test v2 API can be imported."""
    print("\n" + "="*70)
    print("TEST 2: V2 API Imports")
    print("="*70)
    
    try:
        from api.v2.observability import app, compliance_health, regulator_report
        print("✓ FastAPI app imported successfully")
        
        from api.v2.observability import (
            ComplianceHealthResponse,
            RegulatorReportResponse,
            TimelineResponse,
            AnomalyDetectionResponse
        )
        print("✓ Pydantic models imported successfully")
        
        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False


def test_onboarding_wizard_imports():
    """Test onboarding wizard can be imported."""
    print("\n" + "="*70)
    print("TEST 3: Onboarding Wizard Imports")
    print("="*70)
    
    try:
        from onboarding.wizard import OnboardingWizard
        print("✓ OnboardingWizard class imported")
        
        from onboarding.compliance_templates import ComplianceTemplates
        print("✓ ComplianceTemplates class imported")
        
        # Test template generation
        org_info = {
            "org_name": "Test University",
            "org_type": "Research Lab",
            "jurisdiction": "EU",
            "dpo_email": "dpo@test.edu"
        }
        dpa = ComplianceTemplates.generate_dpa_template(org_info)
        assert "Test University" in dpa
        assert "GDPR" in dpa
        print("✓ DPA template generation works")
        
        dataset_info = {
            "id": "ds_test",
            "metadata": {
                "dataset_name": "Test Dataset",
                "data_type": "Genomic Variants (VCF)"
            }
        }
        dpia = ComplianceTemplates.generate_dpia_outline(dataset_info)
        assert "Test Dataset" in dpia
        assert "DPIA" in dpia
        print("✓ DPIA outline generation works")
        
        checklist = ComplianceTemplates.generate_compliance_checklist()
        assert "GDPR" in checklist
        assert "ChaCha20-Poly1305" in checklist
        print("✓ Compliance checklist generation works")
        
        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def test_deployment_files():
    """Test deployment files exist and are valid."""
    print("\n" + "="*70)
    print("TEST 4: Deployment Files")
    print("="*70)
    
    deployment_files = [
        "deployment/Dockerfile",
        "deployment/docker-compose.yml",
        "deployment/nginx.conf",
        "deployment/aws-ecs-task-definition.json",
        "deployment/azure-container-instances.yaml",
        "deployment/gcp-cloud-run.yaml",
        "docs/DEPLOYMENT.md"
    ]
    
    all_exist = True
    for file_path in deployment_files:
        if Path(file_path).exists():
            print(f"✓ {file_path}")
        else:
            print(f"✗ {file_path} MISSING")
            all_exist = False
    
    # Check Dockerfile is multi-stage
    with open("deployment/Dockerfile") as f:
        dockerfile_content = f.read()
        if "FROM python:3.12-slim AS builder" in dockerfile_content:
            print("✓ Dockerfile uses multi-stage build")
        else:
            print("✗ Dockerfile not multi-stage")
            all_exist = False
    
    # Check docker-compose has required services
    with open("deployment/docker-compose.yml") as f:
        compose_content = f.read()
        required_services = ["api-v1", "api-v2", "nginx"]
        for service in required_services:
            if service in compose_content:
                print(f"✓ docker-compose.yml includes {service}")
            else:
                print(f"✗ docker-compose.yml missing {service}")
                all_exist = False
    
    return all_exist


def test_dashboard_v2():
    """Test v2 dashboard exists and has required features."""
    print("\n" + "="*70)
    print("TEST 5: Dashboard v2")
    print("="*70)
    
    dashboard_path = Path("dashboard/v2/index.html")
    if not dashboard_path.exists():
        print("✗ dashboard/v2/index.html not found")
        return False
    
    with open(dashboard_path) as f:
        html_content = f.read()
        
        required_features = [
            "Chart.js",
            "compliance-health",
            "regulator-report",
            "timeline",
            "anomaly-detection"
        ]
        
        all_features = True
        for feature in required_features:
            if feature in html_content:
                print(f"✓ Dashboard includes {feature}")
            else:
                print(f"✗ Dashboard missing {feature}")
                all_features = False
        
        return all_features


def main():
    """Run all validation tests."""
    print("\n🧬 DNA LEDGER VAULT - PHASE 2 VALIDATION")
    print("Testing: Customer Onboarding + Observability Suite + Deployment Kit\n")
    
    tests = [
        ("CLI Integration", test_cli_integration),
        ("V2 API Imports", test_v2_api_imports),
        ("Onboarding Wizard", test_onboarding_wizard_imports),
        ("Deployment Files", test_deployment_files),
        ("Dashboard v2", test_dashboard_v2)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"\n✗ {test_name} EXCEPTION: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*70)
    print("VALIDATION SUMMARY")
    print("="*70)
    
    for test_name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status:10} {test_name}")
    
    total_pass = sum(1 for _, success in results if success)
    total_tests = len(results)
    
    print(f"\nTotal: {total_pass}/{total_tests} tests passed")
    
    if total_pass == total_tests:
        print("\n🎉 Phase 2 implementation validated successfully!")
        return 0
    else:
        print("\n⚠️  Some tests failed. Review output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
