import boto3
import json
import time
import os
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from dotenv import load_dotenv

load_dotenv()
console = Console()

ACCOUNT_ID = "664858858896"
REGION = os.getenv('AWS_REGION', 'ap-south-1')
TARGET_BUCKET = f"detection-lab-target-{ACCOUNT_ID}"

def create_target_bucket(s3):
    """
    Creates a test S3 bucket with sensitive-looking content.
    This simulates a real bucket an attacker would target.
    """
    console.print("\n[cyan]Setting up target environment...[/cyan]")
    
    try:
        # Create the bucket
        s3.create_bucket(
            Bucket=TARGET_BUCKET,
            CreateBucketConfiguration={
                'LocationConstraint': REGION
            }
        )
        console.print(f"[green]Target bucket created: {TARGET_BUCKET}[/green]")
        
        # Upload fake sensitive files
        sensitive_files = {
            "employee-data/employees.csv": "id,name,salary,ssn\n1,John Smith,95000,123-45-6789\n2,Jane Doe,110000,987-65-4321",
            "financial/q4-revenue.txt": "Q4 Revenue Report - CONFIDENTIAL\nTotal Revenue: $4,200,000\nNet Profit: $1,100,000",
            "credentials/api-keys.txt": "SIMULATED FAKE CREDENTIALS - NOT REAL\napi_key=FAKEKEYFORDEMOPURPOSESONLY\napi_secret=FAKESECRETFORDEMOPURPOSESONLY"
        }
        
        for file_key, content in sensitive_files.items():
            s3.put_object(
                Bucket=TARGET_BUCKET,
                Key=file_key,
                Body=content.encode('utf-8')
            )
            console.print(f"[green]Uploaded: {file_key}[/green]")
        
        return True
        
    except Exception as e:
        console.print(f"[red]Setup failed: {str(e)}[/red]")
        return False


def simulate_exfiltration(s3):
    """
    Simulates an attacker discovering and exfiltrating
    data from a misconfigured S3 bucket.
    MITRE ATT&CK T1530 — Data from Cloud Storage
    """
    
    console.print(Panel(
        "[bold red]ATTACK SIMULATION — S3 Data Exfiltration[/bold red]\n"
        "[yellow]MITRE T1530 — Data from Cloud Storage[/yellow]\n"
        "[white]Environment: Personal AWS Lab — Authorized Testing Only[/white]",
        border_style="red"
    ))
    
    results = {}
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Step 1 — Check bucket permissions
    console.print("\n[cyan]Step 1: Checking bucket permissions...[/cyan]")
    time.sleep(1)
    
    try:
        acl = s3.get_bucket_acl(Bucket=TARGET_BUCKET)
        grants = acl.get("Grants", [])
        results["acl_grants"] = len(grants)
        console.print(f"[green]Bucket ACL retrieved — {len(grants)} grants found[/green]")
        
        for grant in grants:
            grantee = grant.get("Grantee", {})
            permission = grant.get("Permission", "unknown")
            grantee_type = grantee.get("Type", "unknown")
            console.print(f"[yellow]Grant: {grantee_type} — {permission}[/yellow]")
            
    except Exception as e:
        console.print(f"[red]Step 1 failed: {str(e)}[/red]")
        results["acl_grants"] = "access_denied"
    
    # Step 2 — List bucket contents
    console.print("\n[cyan]Step 2: Listing bucket contents...[/cyan]")
    time.sleep(1)
    
    try:
        response = s3.list_objects_v2(Bucket=TARGET_BUCKET)
        objects = response.get("Contents", [])
        
        results["files_found"] = [
            {
                "key": obj["Key"],
                "size": obj["Size"],
                "last_modified": str(obj["LastModified"])
            }
            for obj in objects
        ]
        
        # Display found files in a table
        table = Table(title="Files Discovered in Target Bucket")
        table.add_column("File Path", style="cyan")
        table.add_column("Size (bytes)", style="yellow")
        table.add_column("Last Modified", style="white")
        
        for obj in objects:
            table.add_row(
                obj["Key"],
                str(obj["Size"]),
                str(obj["LastModified"])
            )
        
        console.print(table)
        console.print(f"[green]Found {len(objects)} files[/green]")
        
    except Exception as e:
        console.print(f"[red]Step 2 failed: {str(e)}[/red]")
        results["files_found"] = "access_denied"
    
    # Step 3 — Exfiltrate files
    console.print("\n[cyan]Step 3: Exfiltrating discovered files...[/cyan]")
    time.sleep(1)
    
    exfiltrated = []
    
    try:
        for file_info in results.get("files_found", []):
            if isinstance(file_info, dict):
                file_key = file_info["key"]
                
                # Download the file
                obj = s3.get_object(
                    Bucket=TARGET_BUCKET,
                    Key=file_key
                )
                content = obj["Body"].read().decode('utf-8')
                
                exfiltrated.append({
                    "file": file_key,
                    "size": len(content),
                    "preview": content[:50] + "..."
                })
                
                console.print(f"[red]Exfiltrated: {file_key} ({len(content)} bytes)[/red]")
                time.sleep(0.5)
        
        results["exfiltrated"] = exfiltrated
        console.print(f"[red]Total files exfiltrated: {len(exfiltrated)}[/red]")
        
    except Exception as e:
        console.print(f"[red]Step 3 failed: {str(e)}[/red]")
        results["exfiltrated"] = "access_denied"
    
    return results, timestamp

def remediate(s3):
    """
    Remediates the misconfigured bucket after attack simulation.
    Demonstrates the defender response to an S3 exposure.
    """
    console.print("\n[cyan]Remediating misconfigured bucket...[/cyan]")
    
    try:
        # Enable block public access
        s3.put_public_access_block(
            Bucket=TARGET_BUCKET,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        console.print("[green]Block public access enabled[/green]")
        
        # Delete test files
        response = s3.list_objects_v2(Bucket=TARGET_BUCKET)
        objects = response.get("Contents", [])
        
        if objects:
            s3.delete_objects(
                Bucket=TARGET_BUCKET,
                Delete={
                    'Objects': [{'Key': obj['Key']} for obj in objects]
                }
            )
            console.print(f"[green]Deleted {len(objects)} test files[/green]")
        
        # Delete the bucket
        s3.delete_bucket(Bucket=TARGET_BUCKET)
        console.print(f"[green]Target bucket deleted: {TARGET_BUCKET}[/green]")
        console.print("[green]Remediation complete[/green]")
        
    except Exception as e:
        console.print(f"[red]Remediation error: {str(e)}[/red]")


def save_results(results, timestamp):
    """
    Saves attack results to JSON for documentation.
    """
    output_dir = "findings/reports"
    os.makedirs(output_dir, exist_ok=True)
    output_file = f"{output_dir}/scenario2_s3_exfiltration_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    console.print(f"\n[cyan]Results saved to: {output_file}[/cyan]")
    return output_file


def main():
    """
    Main function — orchestrates the full attack simulation.
    Setup → Attack → Document → Remediate
    """
    console.print(Panel(
        "[bold white]AWS Detection Engineering Lab[/bold white]\n"
        "[cyan]Scenario 2 — S3 Data Exfiltration[/cyan]\n"
        "[yellow]All actions performed on owned infrastructure[/yellow]",
        border_style="cyan"
    ))
    
    # Initialize S3 client
    s3 = boto3.client('s3', region_name=REGION)
    
    # Phase 1 — Setup
    console.print("\n[bold cyan]PHASE 1 — ENVIRONMENT SETUP[/bold cyan]")
    setup_success = create_target_bucket(s3)
    
    if not setup_success:
        console.print("[red]Setup failed. Exiting.[/red]")
        return
    
    time.sleep(2)
    
    # Phase 2 — Attack
    console.print("\n[bold red]PHASE 2 — ATTACK SIMULATION[/bold red]")
    results, timestamp = simulate_exfiltration(s3)
    
    # Phase 3 — Document
    console.print("\n[bold cyan]PHASE 3 — DOCUMENTATION[/bold cyan]")
    output_file = save_results(results, timestamp)
    
    # Phase 4 — Remediate
    console.print("\n[bold green]PHASE 4 — REMEDIATION[/bold green]")
    remediate(s3)
    
    # Final summary
    console.print(Panel(
        f"[bold green]SIMULATION COMPLETE[/bold green]\n"
        f"[white]Files discovered: {len(results.get('files_found', []))}[/white]\n"
        f"[white]Files exfiltrated: {len(results.get('exfiltrated', []))}[/white]\n"
        f"[white]Evidence saved: {output_file}[/white]\n"
        f"[yellow]All actions logged to CloudTrail[/yellow]\n"
        f"[yellow]Check GuardDuty for S3 findings[/yellow]\n"
        f"[green]Bucket deleted — environment clean[/green]",
        border_style="green"
    ))


if __name__ == "__main__":
    main()

    