"""
CLI commands for customer onboarding and compliance document generation.
"""

import click
from pathlib import Path
from onboarding.wizard import OnboardingWizard
from onboarding.compliance_templates import ComplianceTemplates


@click.group()
def onboarding():
    """Customer onboarding and compliance tools."""
    pass


@onboarding.command()
@click.option("--out", default="./onboarding_state", help="Output directory for onboarding state")
def wizard(out: str):
    """
    Interactive onboarding wizard for new organizations.
    
    Guides through:
    - Organization profile setup
    - Data steward identity creation
    - First dataset commit
    - Researcher onboarding
    - Consent grant creation
    - Compliance package generation
    
    Example:
        python -m cli.main onboarding wizard --out ./my_org_state
    """
    click.echo("🧬 Starting DNA Ledger Vault Onboarding Wizard...\n")
    
    wizard_instance = OnboardingWizard(output_dir=out)
    wizard_instance.run()


@onboarding.command()
@click.option("--org-name", required=True, help="Organization name")
@click.option("--org-type", default="Research Lab", help="Organization type")
@click.option("--jurisdiction", default="EU", help="Primary jurisdiction (EU, California, etc.)")
@click.option("--dpo-email", default="", help="Data Protection Officer email")
@click.option("--out", default="./dpa_template.md", help="Output file path")
def generate_dpa(org_name: str, org_type: str, jurisdiction: str, dpo_email: str, out: str):
    """
    Generate Data Processing Agreement (DPA) template.
    
    Creates a GDPR Article 28 compliant DPA for review by legal counsel.
    
    Example:
        python -m cli.main onboarding generate-dpa \\
            --org-name "University Medical Center" \\
            --jurisdiction "EU" \\
            --dpo-email "dpo@example.org" \\
            --out ./dpa.md
    """
    org_info = {
        "org_name": org_name,
        "org_type": org_type,
        "jurisdiction": jurisdiction,
        "dpo_email": dpo_email
    }
    
    dpa_content = ComplianceTemplates.generate_dpa_template(org_info)
    
    output_path = Path(out)
    output_path.write_text(dpa_content)
    
    click.echo(f"✓ Data Processing Agreement generated: {output_path}")
    click.echo("\n⚠️  DISCLAIMER: This is a template. Consult legal counsel before use.")


@onboarding.command()
@click.option("--dataset-name", required=True, help="Dataset display name")
@click.option("--dataset-id", required=True, help="Dataset ID (e.g., ds_study_001)")
@click.option("--data-type", default="Genomic Variants (VCF)", help="Type of data")
@click.option("--out", default="./dpia_outline.md", help="Output file path")
def generate_dpia(dataset_name: str, dataset_id: str, data_type: str, out: str):
    """
    Generate Data Protection Impact Assessment (DPIA) outline.
    
    Creates a GDPR Article 35 compliant DPIA template for high-risk processing.
    
    Example:
        python -m cli.main onboarding generate-dpia \\
            --dataset-name "Cancer Genomics Study" \\
            --dataset-id "ds_cancer_2024" \\
            --data-type "Genomic Variants (VCF)" \\
            --out ./dpia.md
    """
    dataset_info = {
        "id": dataset_id,
        "metadata": {
            "dataset_name": dataset_name,
            "data_type": data_type
        }
    }
    
    dpia_content = ComplianceTemplates.generate_dpia_outline(dataset_info)
    
    output_path = Path(out)
    output_path.write_text(dpia_content)
    
    click.echo(f"✓ DPIA outline generated: {output_path}")
    click.echo("\n⚠️  DISCLAIMER: Complete the risk assessment sections with domain experts.")


@onboarding.command()
@click.option("--out", default="./compliance_checklist.csv", help="Output file path")
def generate_checklist(out: str):
    """
    Generate GDPR/CPRA compliance checklist.
    
    Creates a CSV checklist mapping requirements to DNA Ledger Vault features.
    
    Example:
        python -m cli.main onboarding generate-checklist --out ./checklist.csv
    """
    checklist_content = ComplianceTemplates.generate_compliance_checklist()
    
    output_path = Path(out)
    output_path.write_text(checklist_content)
    
    click.echo(f"✓ Compliance checklist generated: {output_path}")
    click.echo(f"  Total requirements: {len(checklist_content.splitlines()) - 1}")
    click.echo("\nOpen in spreadsheet software to track compliance progress.")
