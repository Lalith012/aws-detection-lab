import boto3
import json
import gzip
import os
from datetime import datetime, timedelta, timezone
from rich.console import Console
from rich.table import Table
from dotenv import load_dotenv

load_dotenv()
console = Console()

# Constants
REGION = os.getenv('AWS_REGION', 'ap-south-1')
LOG_BUCKET = "detection-lab-cloudtrail-logs-664858858896"
ACCOUNT_ID = "664858858896"

def get_log_files(hours_back=24):
    """
    Discovers CloudTrail log files in S3 from the last N hours.
    Returns a list of S3 object keys to process.
    """
    console.print(f"\n[cyan]Scanning S3 for CloudTrail logs from last {hours_back} hours...[/cyan]")
    
    s3 = boto3.client('s3', region_name=REGION)
    
    # Calculate time window
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours_back)
    
    # CloudTrail stores logs in this path structure:
    # AWSLogs/{account_id}/CloudTrail/{region}/{year}/{month}/{day}/
    log_files = []
    
    try:
        # Build prefix for current date
        # We search day by day within the time window
        current_date = start_time
        
        while current_date <= end_time:
            prefix = (
                f"AWSLogs/{ACCOUNT_ID}/CloudTrail/{REGION}/"
                f"{current_date.strftime('%Y/%m/%d')}/"
            )
            
            response = s3.list_objects_v2(
                Bucket=LOG_BUCKET,
                Prefix=prefix
            )
            
            objects = response.get('Contents', [])
            
            for obj in objects:
                log_files.append(obj['Key'])
                
            # Move to next day
            current_date += timedelta(days=1)
        
        console.print(f"[green]Found {len(log_files)} log files[/green]")
        return log_files
        
    except Exception as e:
        console.print(f"[red]Error scanning S3: {str(e)}[/red]")
        return []


def download_and_parse_log(s3_key):
    """
    Downloads a single CloudTrail log file from S3,
    decompresses it, and returns the events inside.
    """
    s3 = boto3.client('s3', region_name=REGION)
    
    try:
        # Download the compressed log file
        response = s3.get_object(Bucket=LOG_BUCKET, Key=s3_key)
        compressed_data = response['Body'].read()
        
        # Decompress gzip data
        decompressed_data = gzip.decompress(compressed_data)
        
        # Parse JSON
        log_data = json.loads(decompressed_data.decode('utf-8'))
        
        # CloudTrail wraps events in a "Records" key
        events = log_data.get('Records', [])
        return events
        
    except Exception as e:
        console.print(f"[red]Error reading log {s3_key}: {str(e)}[/red]")
        return []
    
def extract_suspicious_events(events):
    """
    Filters CloudTrail events to find suspicious API calls.
    Focuses on the techniques simulated in Phase 3.
    """
    
    # Define suspicious API calls mapped to MITRE techniques
    suspicious_apis = {
        # T1087.004 — Account Discovery
        'ListUsers': 'T1087.004 — Account Discovery',
        'ListRoles': 'T1087.004 — Account Discovery',
        'ListPolicies': 'T1087.004 — Account Discovery',
        'GetAccountSummary': 'T1087.004 — Account Discovery',
        
        # T1530 — Data from Cloud Storage
        'GetObject': 'T1530 — Data from Cloud Storage',
        'ListObjects': 'T1530 — Data from Cloud Storage',
        'ListObjectsV2': 'T1530 — Data from Cloud Storage',
        
        # T1562.008 — Impair Defenses
        'StopLogging': 'T1562.008 — Impair Defenses',
        'DeleteTrail': 'T1562.008 — Impair Defenses',
        
        # T1078.004 — Valid Accounts
        'ConsoleLogin': 'T1078.004 — Valid Accounts',
        
        # General suspicious
        'CreateAccessKey': 'Persistence — New Access Key',
        'AttachUserPolicy': 'Privilege Escalation — Policy Attachment',
        'PutUserPolicy': 'Privilege Escalation — Inline Policy',
    }
    
    suspicious_found = []
    
    for event in events:
        event_name = event.get('eventName', '')
        
        if event_name in suspicious_apis:
            # Extract key fields from the event
            user_identity = event.get('userIdentity', {})
            
            suspicious_found.append({
                'time': event.get('eventTime', 'unknown'),
                'event': event_name,
                'mitre': suspicious_apis[event_name],
                'user': user_identity.get('userName', 
                        user_identity.get('type', 'unknown')),
                'source_ip': event.get('sourceIPAddress', 'unknown'),
                'user_agent': event.get('userAgent', 'unknown'),
                'region': event.get('awsRegion', 'unknown'),
                'error': event.get('errorCode', None)
            })
    
    return suspicious_found


def display_suspicious_events(suspicious_events):
    """
    Displays suspicious events in a formatted table.
    """
    if not suspicious_events:
        console.print("[yellow]No suspicious events found in time window[/yellow]")
        return
    
    table = Table(title=f"Suspicious CloudTrail Events — {len(suspicious_events)} found")
    
    table.add_column("Time", style="white", no_wrap=True)
    table.add_column("Event", style="red")
    table.add_column("MITRE Technique", style="yellow")
    table.add_column("User", style="cyan")
    table.add_column("Source IP", style="green")
    table.add_column("Error", style="magenta")
    
    for event in suspicious_events:
        table.add_row(
            event['time'][:19],
            event['event'],
            event['mitre'],
            event['user'],
            event['source_ip'],
            event['error'] or 'None'
        )
    
    console.print(table)

def run_analyzer(hours_back=24):
    """
    Main function — orchestrates the full CloudTrail analysis.
    Discovers logs → Downloads → Parses → Detects → Reports
    """
    console.print("\n[bold cyan]CloudTrail Log Analyzer[/bold cyan]")
    console.print("[bold cyan]Detection Engineering Lab — Phase 4[/bold cyan]")
    console.print("=" * 60)
    
    all_events = []
    all_suspicious = []
    
    # Step 1 — Discover log files
    log_files = get_log_files(hours_back=hours_back)
    
    if not log_files:
        console.print("[yellow]No log files found. CloudTrail may not have "
                     "generated logs yet.[/yellow]")
        return
    
    # Step 2 — Download and parse each log file
    console.print(f"\n[cyan]Parsing {len(log_files)} log files...[/cyan]")
    
    for i, log_file in enumerate(log_files, 1):
        console.print(f"[dim]Processing {i}/{len(log_files)}: "
                     f"{log_file.split('/')[-1]}[/dim]")
        
        events = download_and_parse_log(log_file)
        all_events.extend(events)
    
    console.print(f"[green]Total events parsed: {len(all_events)}[/green]")
    
    # Step 3 — Extract suspicious events
    console.print("\n[cyan]Running detection rules...[/cyan]")
    all_suspicious = extract_suspicious_events(all_events)
    
    # Step 4 — Display results
    console.print("\n[cyan]Analysis Results:[/cyan]")
    display_suspicious_events(all_suspicious)
    
    # Step 5 — Save report
    if all_suspicious:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = "findings/reports"
        os.makedirs(output_dir, exist_ok=True)
        output_file = f"{output_dir}/cloudtrail_analysis_{timestamp}.json"
        
        report = {
            "analysis_time": datetime.now(timezone.utc).isoformat(),
            "time_window_hours": hours_back,
            "total_events_processed": len(all_events),
            "suspicious_events_found": len(all_suspicious),
            "findings": all_suspicious
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        console.print(f"\n[cyan]Report saved: {output_file}[/cyan]")
    
    # Summary
    console.print(f"\n[bold green]Analysis Complete[/bold green]")
    console.print(f"[white]Log files processed: {len(log_files)}[/white]")
    console.print(f"[white]Total events analyzed: {len(all_events)}[/white]")
    console.print(f"[white]Suspicious events: {len(all_suspicious)}[/white]")
    
    return all_suspicious


if __name__ == "__main__":
    run_analyzer(hours_back=24)
