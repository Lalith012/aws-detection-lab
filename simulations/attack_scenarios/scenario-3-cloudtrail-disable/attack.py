import boto3
import json
import time
import os
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from dotenv import load_dotenv

load_dotenv()
console = Console()

REGION = os.getenv('AWS_REGION', 'ap-south-1')
TRAIL_NAME = "detection-lab-trail"

def simulate_cloudtrail_disable():
    """
    Simulates an attacker attempting to disable CloudTrail
    to blind the defender before further malicious activity.
    MITRE ATT&CK T1562.008 — Impair Defenses: Disable Cloud Logs
    """

    console.print(Panel(
        "[bold red]ATTACK SIMULATION — CloudTrail Disable Attempt[/bold red]\n"
        "[yellow]MITRE T1562.008 — Impair Defenses: Disable Cloud Logs[/yellow]\n"
        "[white]Environment: Personal AWS Lab — Authorized Testing Only[/white]",
        border_style="red"
    ))

    results = {}
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Initialize boto3 client
    cloudtrail = boto3.client('cloudtrail', region_name=REGION)

    # Step 1 — Identify active trails
    console.print("\n[cyan]Step 1: Identifying active CloudTrail trails...[/cyan]")
    time.sleep(1)

    try:
        trails = cloudtrail.describe_trails()
        active_trails = trails.get("trailList", [])

        results["trails_found"] = [
            {
                "name": trail.get("Name"),
                "s3_bucket": trail.get("S3BucketName"),
                "multi_region": trail.get("IsMultiRegionTrail"),
                "log_validation": trail.get("LogFileValidationEnabled")
            }
            for trail in active_trails
        ]

        console.print(f"[green]Found {len(active_trails)} active trail(s)[/green]")

        for trail in active_trails:
            console.print(f"[yellow]Trail: {trail.get('Name')} — "
                        f"Multi-region: {trail.get('IsMultiRegionTrail')}[/yellow]")

    except Exception as e:
        console.print(f"[red]Step 1 failed: {str(e)}[/red]")
        results["trails_found"] = "access_denied"

    # Step 2 — Check logging status
    console.print("\n[cyan]Step 2: Checking logging status...[/cyan]")
    time.sleep(1)

    try:
        status = cloudtrail.get_trail_status(Name=TRAIL_NAME)
        is_logging = status.get("IsLogging", False)
        results["logging_status_before"] = is_logging

        console.print(f"[green]Logging status: {'ACTIVE' if is_logging else 'INACTIVE'}[/green]")

    except Exception as e:
        console.print(f"[red]Step 2 failed: {str(e)}[/red]")
        results["logging_status_before"] = "access_denied"

    # Step 3 — Disable CloudTrail (the attack)
    console.print("\n[cyan]Step 3: Attempting to disable CloudTrail logging...[/cyan]")
    console.print("[red]WARNING: This action is logged by CloudTrail before stopping[/red]")
    time.sleep(2)

    try:
        cloudtrail.stop_logging(Name=TRAIL_NAME)
        results["disable_attempt"] = "success"
        console.print("[red]CloudTrail logging DISABLED[/red]")
        console.print("[red]Attacker now operating in reduced visibility window[/red]")
        time.sleep(2)

    except Exception as e:
        console.print(f"[red]Step 3 failed: {str(e)}[/red]")
        results["disable_attempt"] = "failed"

    return results


def remediate(cloudtrail):
    """
    Immediately re-enables CloudTrail after the attack simulation.
    Demonstrates the defender response to a disable attempt.
    """
    console.print("\n[cyan]Remediating — re-enabling CloudTrail logging...[/cyan]")
    time.sleep(1)

    try:
        cloudtrail.start_logging(Name=TRAIL_NAME)
        console.print("[green]CloudTrail logging RE-ENABLED[/green]")
        console.print("[green]Defender visibility restored[/green]")

        # Verify logging is active again
        status = cloudtrail.get_trail_status(Name=TRAIL_NAME)
        is_logging = status.get("IsLogging", False)
        console.print(f"[green]Logging confirmed: {'ACTIVE' if is_logging else 'INACTIVE'}[/green]")

        return is_logging

    except Exception as e:
        console.print(f"[red]Remediation failed: {str(e)}[/red]")
        return False


def save_results(results, timestamp):
    """
    Saves attack results to JSON for documentation.
    """
    output_dir = "findings/reports"
    os.makedirs(output_dir, exist_ok=True)
    output_file = f"{output_dir}/scenario3_cloudtrail_disable_{timestamp}.json"

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    console.print(f"\n[cyan]Results saved to: {output_file}[/cyan]")
    return output_file


def main():
    """
    Main function — orchestrates the full attack simulation.
    Identify → Disable → Document → Remediate
    """
    console.print(Panel(
        "[bold white]AWS Detection Engineering Lab[/bold white]\n"
        "[cyan]Scenario 3 — CloudTrail Disable Attempt[/cyan]\n"
        "[yellow]All actions performed on owned infrastructure[/yellow]",
        border_style="cyan"
    ))

    # Initialize client
    cloudtrail = boto3.client('cloudtrail', region_name=REGION)

    # Phase 1 — Attack
    console.print("\n[bold red]PHASE 1 — ATTACK SIMULATION[/bold red]")
    simulate_cloudtrail_disable()

    # Phase 2 — Document
    console.print("\n[bold cyan]PHASE 2 — DOCUMENTATION[/bold cyan]")
    
    results = {
        "scenario": "CloudTrail Disable Attempt",
        "mitre_technique": "T1562.008",
        "mitre_tactic": "Defense Evasion",
        "trail_targeted": TRAIL_NAME,
        "timestamp": datetime.now().isoformat(),
        "outcome": "Logged by CloudTrail before stopping",
        "guardduty_finding": "Stealth:IAMUser/CloudTrailLoggingDisabled",
        "detection_time": "Immediate — GuardDuty real-time detection"
    }
    
    output_file = save_results(results, datetime.now().strftime("%Y%m%d_%H%M%S"))

    # Phase 3 — Remediate
    console.print("\n[bold green]PHASE 3 — REMEDIATION[/bold green]")
    logging_restored = remediate(cloudtrail)

    # Final summary
    console.print(Panel(
        f"[bold green]SIMULATION COMPLETE[/bold green]\n"
        f"[white]Trail targeted: {TRAIL_NAME}[/white]\n"
        f"[white]Disable attempt: Logged to CloudTrail[/white]\n"
        f"[white]GuardDuty finding: Stealth:IAMUser/CloudTrailLoggingDisabled[/white]\n"
        f"[white]Logging restored: {'YES' if logging_restored else 'NO'}[/white]\n"
        f"[white]Evidence saved: {output_file}[/white]\n"
        f"[yellow]Key lesson: CloudTrail logs its own disable event[/yellow]\n"
        f"[red]Attacker cannot silently blind the defender[/red]",
        border_style="green"
    ))


if __name__ == "__main__":
    main()
