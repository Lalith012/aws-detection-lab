# Scenario 3 — CloudTrail Disable Attempt

## MITRE ATT&CK
- **Technique:** T1562.008 — Impair Defenses: Disable Cloud Logs
- **Tactic:** Defense Evasion
- **Severity:** High

## Attack Description
Simulates an attacker attempting to disable CloudTrail logging
to blind the defender before conducting further malicious activity.
Demonstrates why this action is immediately detectable and why
GuardDuty specifically monitors for this behavior.

## Attack Flow

Attacker gains access to AWS account
→ Identifies active CloudTrail trails
→ Attempts to stop logging
→ CloudTrail logs the StopLogging API call
→ GuardDuty raises high severity alert
→ Defender detects and re-enables logging
→ Full incident timeline preserved

## Why This Always Gets Detected
CloudTrail logs its own disable event before stopping.
GuardDuty monitors for StopLogging API calls specifically.
The attacker cannot silently disable logging — the act
of disabling is itself evidence.

## What Gets Detected
- CloudTrail: StopLogging API call with timestamp and identity
- GuardDuty: Stealth:IAMUser/CloudTrailLoggingDisabled
- Security Hub: Critical finding aggregated

## Evidence Location
- CloudTrail logs: S3 bucket detection-lab-cloudtrail-logs-664858858896
- GuardDuty findings: findings/reports/
- Attack script output: findings/reports/

## Remediation
- Immediately re-enable CloudTrail logging
- Rotate credentials of compromised identity
- Review all API calls between disable and re-enable
- Implement CloudWatch alarm for StopLogging events
- Use AWS Organizations SCPs to prevent CloudTrail disable

## Azure Equivalent
- Azure Monitor — Diagnostic settings disable detection
- Microsoft Sentinel — Azure Activity log monitoring
- Azure Policy — Enforce diagnostic settings
