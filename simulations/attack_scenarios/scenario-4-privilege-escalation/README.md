# Scenario 4 — Privilege Escalation

## MITRE ATT&CK
- **Technique:** T1548 — Abuse Elevation Control Mechanism
- **Tactic:** Privilege Escalation
- **Severity:** High

## Attack Description
Simulates an attacker attempting to escalate privileges in an AWS
account after gaining initial access. Demonstrates common privilege
escalation techniques including policy attachment and backdoor user
creation. All attempts are logged by CloudTrail regardless of success
or failure.

## Attack Flow

Attacker gains initial access with limited permissions

→ Check current identity and permissions

→ Attempt to attach AdministratorAccess policy to own user

→ Attempt to create new backdoor admin user

→ CloudTrail logs all IAM modification attempts

→ GuardDuty detects unusual IAM activity

→ Detection rule DR-004 fires — Privilege Escalation Attempt

→ Remediate — remove unauthorized policy attachments

## Why Failed Attempts Still Get Detected
CloudTrail records both successful and failed API calls.
An AccessDenied error on AttachUserPolicy is itself evidence
of an escalation attempt. Defenders look for failed privileged
calls as indicators of compromise.

## What Gets Detected
- CloudTrail: AttachUserPolicy, CreateUser, PutUserPolicy API calls
- Both successful and failed attempts are logged
- GuardDuty: UnauthorizedAccess findings
- Detection rule DR-004 fires on any policy attachment attempt

## Evidence Location
- CloudTrail logs: S3 bucket detection-lab-cloudtrail-logs-664858858896
- Attack script output: findings/reports/
- MITRE mapping: docs/mitre-mapping.md

## Remediation
- Remove any unauthorized policy attachments immediately
- Delete any backdoor users created
- Rotate credentials of compromised identity
- Review all IAM changes in the last 24 hours
- Implement SCPs to prevent unauthorized policy attachments

## Azure Equivalent
- Azure AD — Privileged Identity Management (PIM)
- Microsoft Sentinel — Privileged role assignment detection
- Azure Policy — Restrict role assignment permissions