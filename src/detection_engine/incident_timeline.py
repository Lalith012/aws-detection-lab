import json
import os
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from dotenv import load_dotenv

load_dotenv()
console = Console()

# Severity ordering for sorting
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3
}

def build_timeline(triggered_rules, suspicious_events):
    """
    Builds a chronological incident timeline from
    triggered rules and suspicious events.
    """
    console.print("\n[bold cyan]Building Incident Timeline...[/bold cyan]")
    
    if not triggered_rules:
        console.print("[green]No incidents to timeline — environment clean[/green]")
        return None
    
    # Collect all events with their rule context
    timeline_events = []
    
    for triggered in triggered_rules:
        rule = triggered["rule"]
        
        for event in triggered["matched_events"]:
            timeline_events.append({
                "time": event["time"],
                "event": event["event"],
                "user": event["user"],
                "source_ip": event["source_ip"],
                "error": event["error"],
                "rule_id": rule["rule_id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "mitre": rule["mitre_technique"],
                "tactic": rule["mitre_tactic"]
            })
    
    # Sort chronologically by time
    timeline_events.sort(key=lambda x: x["time"])
    
    # Calculate incident duration
    if len(timeline_events) > 1:
        first_event = timeline_events[0]["time"]
        last_event = timeline_events[-1]["time"]
        
        first_dt = datetime.fromisoformat(
            first_event.replace('Z', '+00:00')
        )
        last_dt = datetime.fromisoformat(
            last_event.replace('Z', '+00:00')
        )
        
        duration = last_dt - first_dt
        duration_str = str(duration)
    else:
        duration_str = "Single event"
    
    # Build timeline object
    timeline = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_events": len(timeline_events),
        "duration": duration_str,
        "tactics_observed": list(set(
            e["tactic"] for e in timeline_events
        )),
        "techniques_observed": list(set(
            e["mitre"] for e in timeline_events
        )),
        "identities_involved": list(set(
            e["user"] for e in timeline_events
        )),
        "source_ips": list(set(
            e["source_ip"] for e in timeline_events
        )),
        "events": timeline_events
    }
    
    return timeline

def display_timeline(timeline):
    """
    Displays the incident timeline in a professional format.
    """
    if not timeline:
        return
    
    # Header
    console.print(Panel(
        f"[bold red]INCIDENT TIMELINE REPORT[/bold red]\n"
        f"[white]Generated: {timeline['generated_at'][:19]}[/white]\n"
        f"[white]Total Events: {timeline['total_events']}[/white]\n"
        f"[white]Duration: {timeline['duration']}[/white]\n"
        f"[yellow]Tactics: {', '.join(timeline['tactics_observed'])}[/yellow]\n"
        f"[yellow]Techniques: {', '.join(timeline['techniques_observed'])}[/yellow]\n"
        f"[cyan]Identities: {', '.join(timeline['identities_involved'])}[/cyan]\n"
        f"[cyan]Source IPs: {', '.join(timeline['source_ips'])}[/cyan]",
        border_style="red",
        title="INCIDENT REPORT"
    ))
    
    # Timeline table
    table = Table(
        title="Chronological Event Timeline",
        show_lines=True
    )
    
    table.add_column("#", style="dim", width=4)
    table.add_column("Time", style="white", no_wrap=True)
    table.add_column("Event", style="red")
    table.add_column("Rule", style="yellow")
    table.add_column("Severity", style="white")
    table.add_column("MITRE", style="cyan")
    table.add_column("User", style="green")
    table.add_column("Source IP", style="blue")
    
    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange3",
        "MEDIUM": "yellow",
        "LOW": "green"
    }
    
    for i, event in enumerate(timeline["events"], 1):
        color = severity_colors.get(event["severity"], "white")
        table.add_row(
            str(i),
            event["time"][:19],
            event["event"],
            event["rule_id"],
            f"[{color}]{event['severity']}[/{color}]",
            event["mitre"],
            event["user"],
            event["source_ip"]
        )
    
    console.print(table)
    
    # Attack narrative
    console.print("\n[bold cyan]Attack Narrative:[/bold cyan]")
    console.print("[dim]Based on observed events:[/dim]\n")
    
    tactics = timeline["tactics_observed"]
    techniques = timeline["techniques_observed"]
    identities = timeline["identities_involved"]
    ips = timeline["source_ips"]
    
    narrative = (
        f"The incident involved {len(timeline['events'])} suspicious "
        f"event(s) over {timeline['duration']}. "
        f"Identity '{', '.join(identities)}' performed actions from "
        f"IP address(es) {', '.join(ips)}. "
        f"Observed tactics include {', '.join(tactics)}. "
        f"MITRE ATT&CK techniques identified: {', '.join(techniques)}."
    )
    
    console.print(f"[white]{narrative}[/white]")


def save_timeline(timeline):
    """
    Saves the incident timeline to JSON.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir = "findings/reports"
    os.makedirs(output_dir, exist_ok=True)
    output_file = f"{output_dir}/incident_timeline_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(timeline, f, indent=2, default=str)
    
    console.print(f"\n[cyan]Timeline saved: {output_file}[/cyan]")
    return output_file


def run_timeline_builder(triggered_rules, suspicious_events):
    """
    Main function — builds and displays the incident timeline.
    """
    console.print("\n[bold cyan]Incident Timeline Builder[/bold cyan]")
    console.print("[bold cyan]Detection Engineering Lab — Phase 4[/bold cyan]")
    console.print("=" * 60)
    
    timeline = build_timeline(triggered_rules, suspicious_events)
    
    if timeline:
        display_timeline(timeline)
        save_timeline(timeline)
    
    return timeline


if __name__ == "__main__":
    import glob
    import sys
    
    # Load latest rule report
    reports = glob.glob("findings/reports/detection_rules_*.json")
    analyzer_reports = glob.glob("findings/reports/cloudtrail_analysis_*.json")
    
    if not reports or not analyzer_reports:
        console.print("[red]Run cloudtrail_analyzer.py and "
                     "detection_rules.py first.[/red]")
        sys.exit(1)
    
    latest_rules = max(reports)
    latest_analysis = max(analyzer_reports)
    
    console.print(f"[cyan]Loading rule report: {latest_rules}[/cyan]")
    console.print(f"[cyan]Loading analysis: {latest_analysis}[/cyan]")
    
    with open(latest_rules) as f:
        rule_report = json.load(f)
    
    with open(latest_analysis) as f:
        analysis_report = json.load(f)
    
    # Reconstruct triggered rules format for timeline
    triggered_rules = []
    for finding in rule_report.get("findings", []):
        triggered_rules.append({
            "rule": {
                "rule_id": finding["rule_id"],
                "name": finding["rule_name"],
                "severity": finding["severity"],
                "confidence": finding["confidence"],
                "mitre_technique": finding["mitre_technique"],
                "mitre_tactic": finding["mitre_tactic"],
                "response": finding["response"]
            },
            "matched_events": finding["matched_events"],
            "event_count": finding["event_count"],
            "triggered_at": finding["triggered_at"]
        })
    
    suspicious_events = analysis_report.get("findings", [])
    
    run_timeline_builder(triggered_rules, suspicious_events)