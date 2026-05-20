# Scenario 1 — IAM Credential Reconnaissance

## MITRE ATT&CK
- **Technique:** T1087.004 — Account Discovery: Cloud Account
- **Tactic:** Discovery
- **Severity:** Low-Medium

## Attack Description
Simulates the reconnaissance phase of an AWS compromise.
After gaining initial access, an attacker enumerates IAM users,
roles, and policies to understand the environment and identify
privilege escalation paths.

## Attack Flow

Initial Access (stolen credentials)

→ GetCallerIdentity — Confirm identity

→ ListUsers — Map all IAM users

→ ListRoles — Find assumable roles

→ ListPolicies — Identify permissions

→ GetAccountSummary — Understand account scope
## What Gets Detected
- CloudTrail logs every API call with timestamp and source IP
- GuardDuty flags rapid enumeration as suspicious behavior
- Security Hub aggregates the finding

## Evidence Location
- CloudTrail logs: S3 bucket detection-lab-cloudtrail-logs-664858858896
- GuardDuty findings: findings/reports/
- Attack script: attack.py

## Remediation
- Rotate compromised credentials immediately
- Enable MFA on all IAM users
- Implement least privilege — remove unused permissions
- Set up CloudWatch alarms for enumeration patterns

## Azure Equivalent
- Azure AD — Identity Protection detects enumeration
- Microsoft Sentinel — UEBA detects unusual API patterns