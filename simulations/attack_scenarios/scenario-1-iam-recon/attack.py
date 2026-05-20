import boto3
import json
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from dotenv import load_dotenv
import os

load_dotenv()
console = Console()

def run_iam_recon():
    """
    Simulates IAM reconnaissance performed by an attacker
    after gaining initial access to an AWS account.
    MITRE ATT&CK T1087.004 — Account Discovery: Cloud Account
    """

    console.print(Panel(
        "[bold red]ATTACK SIMULATION — IAM Reconnaissance[/bold red]\n"
        "[yellow]MITRE T1087.004 — Account Discovery: Cloud Account[/yellow]\n"
        "[white]Environment: Personal AWS Lab — Authorized Testing Only[/white]",
        border_style="red"
    ))

    results = {}
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Initialize boto3 clients
    sts = boto3.client('sts', region_name=os.getenv('AWS_REGION', 'ap-south-1'))
    iam = boto3.client('iam', region_name=os.getenv('AWS_REGION', 'ap-south-1'))

    # Step 1 — Who am I?
    console.print("\n[cyan]Step 1: Identifying compromised identity...[/cyan]")
    time.sleep(1)
    try:
        identity = sts.get_caller_identity()
        results["identity"] = {
            "account": identity["Account"],
            "user_id": identity["UserId"],
            "arn": identity["Arn"]
        }
        console.print(f"[green]Identity confirmed: {identity['Arn']}[/green]")
    except Exception as e:
        console.print(f"[red]Step 1 failed: {str(e)}[/red]")
        results["identity"] = "access_denied"

    # Step 2 — Who else exists?
    console.print("\n[cyan]Step 2: Enumerating IAM users...[/cyan]")
    time.sleep(1)
    try:
        users_response = iam.list_users()
        results["users"] = [
            {
                "username": user["UserName"],
                "user_id": user["UserId"],
                "arn": user["Arn"],
                "created": str(user["CreateDate"])
            }
            for user in users_response["Users"]
        ]
        console.print(f"[green]Found {len(results['users'])} IAM users[/green]")
    except Exception as e:
        console.print(f"[red]Step 2 failed: {str(e)}[/red]")
        results["users"] = "access_denied"

    # Step 3 — What roles can I assume?
    console.print("\n[cyan]Step 3: Enumerating IAM roles...[/cyan]")
    time.sleep(1)
    try:
        roles_response = iam.list_roles()
        results["roles"] = [
            {
                "name": role["RoleName"],
                "arn": role["Arn"],
                "created": str(role["CreateDate"])
            }
            for role in roles_response["Roles"]
        ]
        console.print(f"[green]Found {len(results['roles'])} IAM roles[/green]")
    except Exception as e:
        console.print(f"[red]Step 3 failed — insufficient permissions: {str(e)}[/red]")
        results["roles"] = "access_denied"

    # Step 4 — What policies exist?
    console.print("\n[cyan]Step 4: Enumerating IAM policies...[/cyan]")
    time.sleep(1)
    try:
        policies_response = iam.list_policies(Scope='Local')
        results["policies"] = [
            {
                "name": policy.get("PolicyName", "unknown"),
                "arn": policy.get("Arn", policy.get("PolicyArn", "unknown")),
                "attached_count": policy.get("AttachmentCount", 0)
            }
            for policy in policies_response["Policies"]
        ]
        console.print(f"[green]Found {len(results['policies'])} custom policies[/green]")
    except Exception as e:
        console.print(f"[red]Step 4 failed: {str(e)}[/red]")
        results["policies"] = "access_denied"

    # Step 5 — Account summary
    console.print("\n[cyan]Step 5: Retrieving account summary...[/cyan]")
    time.sleep(1)
    try:
        summary = iam.get_account_summary()
        results["account_summary"] = {
            "users_count": summary["SummaryMap"].get("Users", 0),
            "groups_count": summary["SummaryMap"].get("Groups", 0),
            "roles_count": summary["SummaryMap"].get("Roles", 0),
            "policies_count": summary["SummaryMap"].get("Policies", 0),
            "mfa_enabled": summary["SummaryMap"].get("AccountMFAEnabled", 0)
        }
        console.print(f"[green]Account summary retrieved[/green]")
    except Exception as e:
        console.print(f"[red]Step 5 failed: {str(e)}[/red]")
        results["account_summary"] = "access_denied"

    # Save results to file
    output_dir = "findings/reports"
    os.makedirs(output_dir, exist_ok=True)
    output_file = f"{output_dir}/scenario1_iam_recon_{timestamp}.json"

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    console.print(f"\n[cyan]Results saved to: {output_file}[/cyan]")

    # Summary panel
    def safe_count(value):
        return len(value) if isinstance(value, list) else "access_denied"

    console.print(Panel(
        f"[bold green]RECONNAISSANCE COMPLETE[/bold green]\n"
        f"[white]Identity: {results['identity'] if results['identity'] == 'access_denied' else results['identity']['arn']}[/white]\n"
        f"[white]Users found: {safe_count(results['users'])}[/white]\n"
        f"[white]Roles found: {safe_count(results['roles'])}[/white]\n"
        f"[white]Custom policies: {safe_count(results['policies'])}[/white]\n"
        f"[yellow]All API calls logged to CloudTrail[/yellow]\n"
        f"[yellow]GuardDuty monitoring for suspicious patterns[/yellow]",
        border_style="green"
    ))

if __name__ == "__main__":
    run_iam_recon()