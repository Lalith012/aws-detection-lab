import json
import os
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Detection Rules — each rule is a dictionary defining
# what to look for and how to respond
DETECTION_RULES = [
    {
        "rule_id": "DR-001",
        "name": "CloudTrail Logging Disabled",
        "description": "Detects attempt to disable CloudTrail logging — "
                      "classic defense evasion technique",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "mitre_technique": "T1562.008",
        "mitre_tactic": "Defense Evasion",
        "trigger_events": ["StopLogging", "DeleteTrail"],
        "response": [
            "Immediately re-enable CloudTrail logging",
            "Rotate credentials of identity that disabled logging",
            "Review all API calls in the disable window",
            "Check for other indicators of compromise"
        ]
    },
    {
        "rule_id": "DR-002",
        "name": "IAM Reconnaissance Detected",
        "description": "Multiple IAM enumeration API calls indicating "
                      "attacker mapping the environment",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "mitre_technique": "T1087.004",
        "mitre_tactic": "Discovery",
        "trigger_events": ["ListUsers", "ListRoles", 
                          "ListPolicies", "GetAccountSummary"],
        "response": [
            "Review identity performing enumeration",
            "Check if enumeration source IP is expected",
            "Verify no privilege escalation followed",
            "Consider implementing SCPs to restrict IAM enumeration"
        ]
    },
    {
        "rule_id": "DR-003",
        "name": "S3 Data Access — Potential Exfiltration",
        "description": "Unusual S3 object access pattern indicating "
                      "potential data exfiltration",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "mitre_technique": "T1530",
        "mitre_tactic": "Collection",
        "trigger_events": ["GetObject", "ListObjects", "ListObjectsV2"],
        "response": [
            "Identify which bucket and objects were accessed",
            "Check if accessing identity has legitimate need",
            "Review bucket policy and ACL configuration",
            "Enable S3 Block Public Access if not already enabled",
            "Check for bulk download patterns"
        ]
    },
    {
        "rule_id": "DR-004",
        "name": "Privilege Escalation Attempt",
        "description": "IAM policy attachment detected — "
                      "possible privilege escalation",
        "severity": "HIGH",
        "confidence": "HIGH",
        "mitre_technique": "T1548",
        "mitre_tactic": "Privilege Escalation",
        "trigger_events": ["AttachUserPolicy", "PutUserPolicy",
                          "AttachRolePolicy", "CreateAccessKey"],
        "response": [
            "Immediately review the policy that was attached",
            "Verify the identity performing the action is authorized",
            "Check if new permissions were used after attachment",
            "Remove unauthorized policy attachments",
            "Review IAM activity for the last 24 hours"
        ]
    },
    {
        "rule_id": "DR-005",
        "name": "Root Account Usage",
        "description": "AWS root account used for API calls — "
                      "violates security best practices",
        "severity": "HIGH",
        "confidence": "HIGH",
        "mitre_technique": "T1078.004",
        "mitre_tactic": "Initial Access",
        "trigger_events": ["ConsoleLogin"],
        "response": [
            "Verify if root usage was authorized",
            "Enable MFA on root account immediately if not enabled",
            "Create IAM users for all programmatic access",
            "Disable root account access keys",
            "Review what actions were taken with root credentials"
        ]
    }
]

def match_rules(suspicious_events):
    """
    Matches suspicious events against detection rules.
    Returns a list of triggered rules with matched events.
    """
    triggered_rules = []
    
    for rule in DETECTION_RULES:
        matched_events = []
        
        for event in suspicious_events:
            if event['event'] in rule['trigger_events']:
                matched_events.append(event)
        
        if matched_events:
            triggered_rules.append({
                "rule": rule,
                "matched_events": matched_events,
                "triggered_at": datetime.now(timezone.utc).isoformat(),
                "event_count": len(matched_events)
            })
    
    return triggered_rules


def calculate_risk_score(triggered_rules):
    """
    Calculates an overall risk score based on triggered rules.
    Higher score = higher risk to the environment.
    """
    severity_scores = {
        "CRITICAL": 40,
        "HIGH": 25,
        "MEDIUM": 10,
        "LOW": 5
    }
    
    confidence_multipliers = {
        "HIGH": 1.0,
        "MEDIUM": 0.7,
        "LOW": 0.4
    }
    
    total_score = 0
    
    for triggered in triggered_rules:
        rule = triggered["rule"]
        severity = rule["severity"]
        confidence = rule["confidence"]
        event_count = triggered["event_count"]
        
        base_score = severity_scores.get(severity, 0)
        multiplier = confidence_multipliers.get(confidence, 0.5)
        
        # Multiple events of same type increase score
        event_multiplier = min(event_count, 3)
        
        rule_score = base_score * multiplier * event_multiplier
        total_score += rule_score
    
    return round(total_score, 1)


def get_risk_level(score):
    """
    Converts numeric risk score to human readable level.
    """
    if score >= 80:
        return "CRITICAL", "red"
    elif score >= 50:
        return "HIGH", "orange3"
    elif score >= 25:
        return "MEDIUM", "yellow"
    elif score > 0:
        return "LOW", "green"
    else:
        return "NONE", "dim"
    
def display_triggered_rules(triggered_rules, risk_score):
    """
    Displays triggered detection rules with full context.
    """
    if not triggered_rules:
        console.print(Panel(
            "[green]No detection rules triggered[/green]\n"
            "[dim]Environment appears clean[/dim]",
            border_style="green"
        ))
        return
    
    risk_level, risk_color = get_risk_level(risk_score)
    
    # Overall risk summary
    console.print(Panel(
        f"[bold {risk_color}]RISK LEVEL: {risk_level}[/bold {risk_color}]\n"
        f"[white]Risk Score: {risk_score}[/white]\n"
        f"[white]Rules Triggered: {len(triggered_rules)}[/white]",
        border_style=risk_color
    ))
    
    # Detail for each triggered rule
    for triggered in triggered_rules:
        rule = triggered["rule"]
        events = triggered["matched_events"]
        
        # Rule header
        severity = rule["severity"]
        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "green"
        }
        color = severity_colors.get(severity, "white")
        
        console.print(f"\n[bold {color}]"
                     f"[{rule['rule_id']}] {rule['name']}[/bold {color}]")
        console.print(f"[dim]Severity: {severity} | "
                     f"Confidence: {rule['confidence']} | "
                     f"MITRE: {rule['mitre_technique']} — "
                     f"{rule['mitre_tactic']}[/dim]")
        console.print(f"[white]{rule['description']}[/white]")
        
        # Matched events table
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Time", style="white")
        table.add_column("Event", style=color)
        table.add_column("User", style="cyan")
        table.add_column("Source IP", style="green")
        table.add_column("Error", style="magenta")
        
        for event in events:
            table.add_row(
                event['time'][:19],
                event['event'],
                event['user'],
                event['source_ip'],
                event['error'] or 'None'
            )
        
        console.print(table)
        
        # Response recommendations
        console.print(f"[bold cyan]Recommended Response:[/bold cyan]")
        for i, action in enumerate(rule['response'], 1):
            console.print(f"  [cyan]{i}.[/cyan] {action}")


def save_rule_report(triggered_rules, risk_score):
    """
    Saves the detection rule report to JSON.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir = "findings/reports"
    os.makedirs(output_dir, exist_ok=True)
    output_file = f"{output_dir}/detection_rules_{timestamp}.json"
    
    risk_level, _ = get_risk_level(risk_score)
    
    report = {
        "report_time": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "rules_triggered": len(triggered_rules),
        "findings": [
            {
                "rule_id": t["rule"]["rule_id"],
                "rule_name": t["rule"]["name"],
                "severity": t["rule"]["severity"],
                "confidence": t["rule"]["confidence"],
                "mitre_technique": t["rule"]["mitre_technique"],
                "mitre_tactic": t["rule"]["mitre_tactic"],
                "event_count": t["event_count"],
                "triggered_at": t["triggered_at"],
                "matched_events": t["matched_events"],
                "response": t["rule"]["response"]
            }
            for t in triggered_rules
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    console.print(f"\n[cyan]Report saved: {output_file}[/cyan]")
    return output_file


def run_rule_engine(suspicious_events):
    """
    Main function — runs the full detection rule engine.
    """
    console.print("\n[bold cyan]Detection Rule Engine[/bold cyan]")
    console.print("[bold cyan]Detection Engineering Lab — Phase 4[/bold cyan]")
    console.print("=" * 60)
    
    # Match events against rules
    console.print("\n[cyan]Matching events against detection rules...[/cyan]")
    triggered_rules = match_rules(suspicious_events)
    
    # Calculate risk score
    risk_score = calculate_risk_score(triggered_rules)
    
    # Display results
    display_triggered_rules(triggered_rules, risk_score)
    
    # Save report
    if triggered_rules:
        save_rule_report(triggered_rules, risk_score)
    
    return triggered_rules, risk_score


if __name__ == "__main__":
    # For testing — load suspicious events from analyzer output
    import glob
    
    reports = glob.glob("findings/reports/cloudtrail_analysis_*.json")
    
    if not reports:
        console.print("[red]No analyzer reports found. "
                     "Run cloudtrail_analyzer.py first.[/red]")
    else:
        latest = max(reports)
        console.print(f"[cyan]Loading analyzer report: {latest}[/cyan]")
        
        with open(latest) as f:
            report = json.load(f)
        
        suspicious_events = report.get("findings", [])
        run_rule_engine(suspicious_events)