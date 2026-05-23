# Attack Scenarios Documentation

All attack simulations performed exclusively on owned AWS infrastructure.
See DISCLAIMER.md for full legal context.

---

## Scenario 1 — IAM Credential Reconnaissance

**MITRE:** T1087.004 — Account Discovery: Cloud Account
**Tactic:** Discovery
**Severity:** Low-Medium

### What it simulates
After gaining initial access to an AWS account an attacker enumerates
IAM users, roles, and policies to understand the environment and identify
privilege escalation paths. This is the first action in most real AWS
compromises.

### Attack flow
1. GetCallerIdentity — confirm compromised identity
2. ListUsers — enumerate all IAM users
3. ListRoles — find assumable roles
4. ListPolicies — identify custom permission sets
5. GetAccountSummary — understand account scope

### Detection
- CloudTrail logs every API call with timestamp and source IP
- GuardDuty flags rapid enumeration patterns
- Custom detection rule DR-002 fires on IAM enumeration

### Key learning
Graceful degradation — script continues collecting available data
even when some API calls fail due to insufficient permissions.

---

## Scenario 2 — S3 Data Exfiltration

**MITRE:** T1530 — Data from Cloud Storage
**Tactic:** Collection
**Severity:** High

### What it simulates
Attacker discovers and exfiltrates data from a misconfigured S3 bucket.
Demonstrates how improper bucket policies lead to unauthorized data
access. Mirrors real-world breaches like Capital One (2019).

### Attack flow
1. Create target bucket with sensitive test files
2. GetBucketAcl — check bucket permissions
3. ListObjectsV2 — enumerate bucket contents
4. GetObject — download files (credentials, financial data, employee data)
5. Remediate — enable Block Public Access, delete test resources

### Detection
- CloudTrail logs GetBucketAcl, ListObjectsV2, GetObject
- Custom detection rule DR-003 fires on S3 access pattern
- Splunk dashboard Panel 3 shows access pattern

### Key learning
Attackers prioritize credential files over financial data because
credentials enable persistence and lateral movement.

---

## Scenario 3 — CloudTrail Disable Attempt

**MITRE:** T1562.008 — Impair Defenses: Disable Cloud Logs
**Tactic:** Defense Evasion
**Severity:** Critical

### What it simulates
Attacker attempts to disable CloudTrail logging to blind the defender
before conducting further malicious activity. Demonstrates why this
technique always gets detected.

### Attack flow
1. DescribeTrails — identify active trails
2. GetTrailStatus — confirm logging is active
3. StopLogging — attempt to disable logging
4. CloudTrail logs the StopLogging event before stopping
5. GuardDuty raises Stealth:IAMUser/CloudTrailLoggingDisabled
6. Remediation — re-enable logging immediately

### Detection
- CloudTrail records StopLogging before it stops — self-defeating attack
- GuardDuty finding: Stealth:IAMUser/CloudTrailLoggingDisabled
- Custom detection rule DR-001 CRITICAL severity fires immediately
- Splunk dashboard Panel 1 shows the event

### Key learning
CloudTrail logs its own disable event. An attacker cannot silently
blind the defender — the attempt itself is permanent evidence.

---

## MITRE ATT&CK Coverage Summary

| Technique | Tactic | Scenario | Detection Rule |
|---|---|---|---|
| T1078.004 | Initial Access | Live GuardDuty finding | DR-005 |
| T1087.004 | Discovery | Scenario 1 | DR-002 |
| T1530 | Collection | Scenario 2 | DR-003 |
| T1562.008 | Defense Evasion | Scenario 3 | DR-001 |