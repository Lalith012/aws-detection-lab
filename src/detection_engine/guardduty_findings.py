import boto3
import json
from datetime import datetime
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich import print as rprint
import os

# Load environment variables from .env file
load_dotenv()

# Initialize rich console for clean output
console = Console()

def get_guardduty_findings():
    """
    Connects to AWS GuardDuty and retrieves all current findings.
    This is the core function of the detection engine.
    """
    
    # Initialize boto3 client for GuardDuty
    # boto3 automatically uses credentials from AWS CLI configuration
    guardduty = boto3.client(
        'guardduty',
        region_name=os.getenv('AWS_REGION', 'ap-south-1')
    )
    
    try:
        # Step 1: Get detector ID
        # Every GuardDuty setup has a detector - this is its unique identifier
        console.print("[cyan]Connecting to GuardDuty...[/cyan]")
        
        detectors = guardduty.list_detectors()
        
        if not detectors['DetectorIds']:
            console.print("[red]No GuardDuty detector found. Enable GuardDuty first.[/red]")
            return
        
        detector_id = detectors['DetectorIds'][0]
        console.print(f"[green]Detector found: {detector_id}[/green]")
        
        # Step 2: List all finding IDs
        console.print("[cyan]Retrieving findings...[/cyan]")
        
        findings_response = guardduty.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                'Criterion': {
                    'severity': {
                        # Pull findings with severity 4 and above
                        # GuardDuty severity: 1-3 low, 4-6 medium, 7-8 high
                        'Gte': 1
                    }
                }
            },
            MaxResults=50
        )
        
        finding_ids = findings_response.get('FindingIds', [])
        
        if not finding_ids:
            console.print("[yellow]No findings detected yet. This is normal for a new environment.[/yellow]")
            console.print("[yellow]Findings will appear after attack simulations in Phase 3.[/yellow]")
            return
        
        # Step 3: Get detailed information for each finding
        findings = guardduty.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids
        )
        
        # Step 4: Display findings in a formatted table
        display_findings(findings['Findings'])
        
        # Step 5: Save findings to JSON for further analysis
        save_findings(findings['Findings'])
        
    except Exception as e:
        console.print(f"[red]Error connecting to GuardDuty: {str(e)}[/red]")
        raise

def display_findings(findings):
    """
    Displays GuardDuty findings in a formatted table.
    """
    table = Table(title="GuardDuty Findings")
    
    table.add_column("Severity", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Title", style="green")
    table.add_column("Region", style="yellow")
    table.add_column("Time", style="white")
    
    for finding in findings:
        severity = str(finding.get('Severity', 'N/A'))
        finding_type = finding.get('Type', 'N/A')
        title = finding.get('Title', 'N/A')
        region = finding.get('Region', 'N/A')
        time = finding.get('UpdatedAt', 'N/A')
        
        # Color code by severity
        if float(severity) >= 7:
            severity_display = f"[red]{severity} HIGH[/red]"
        elif float(severity) >= 4:
            severity_display = f"[yellow]{severity} MEDIUM[/yellow]"
        else:
            severity_display = f"[green]{severity} LOW[/green]"
        
        table.add_row(severity_display, finding_type, title, region, time)
    
    console.print(table)
    console.print(f"[green]Total findings: {len(findings)}[/green]")

def save_findings(findings):
    """
    Saves findings to a JSON file for further analysis and documentation.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"findings/reports/guardduty_findings_{timestamp}.json"
    
    os.makedirs("findings/reports", exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    
    console.print(f"[cyan]Findings saved to: {output_file}[/cyan]")

if __name__ == "__main__":
    console.print("[bold cyan]AWS Detection Engineering Lab[/bold cyan]")
    console.print("[bold cyan]GuardDuty Findings Analyzer[/bold cyan]")
    console.print("=" * 50)
    get_guardduty_findings()