# Splunk SPL Detection Queries
Generated from Sigma rules using sigma-cli

## Usage
Add `| spath |` after index search for nested JSON parsing.
Set time range to All Time for full coverage.

---

## DR-001 — CloudTrail Logging Disabled
**MITRE:** T1562.008 — Defense Evasion
**Severity:** Critical

```spl
index="cloudtrail-logs" | spath | search
eventSource="cloudtrail.amazonaws.com"
eventName IN ("StopLogging", "DeleteTrail")
| table eventName, userIdentity.userName,
  sourceIPAddress, awsRegion, eventTime
```

**Expected findings:** StopLogging or DeleteTrail by any identity

---

## DR-002 — IAM Reconnaissance
**MITRE:** T1087.004 — Discovery
**Severity:** Medium

```spl
index="cloudtrail-logs" | spath | search
eventSource="iam.amazonaws.com"
eventName IN ("ListUsers","ListRoles","ListPolicies","GetAccountSummary")
| table eventName, userIdentity.userName,
  sourceIPAddress, awsRegion, eventTime
```

**Expected findings:** Multiple IAM enumeration calls in sequence

---

## DR-003 — S3 Data Exfiltration
**MITRE:** T1530 — Collection
**Severity:** High

```spl
index="cloudtrail-logs" | spath | search
eventSource="s3.amazonaws.com"
eventName IN ("GetObject","ListObjects","ListObjectsV2","GetBucketAcl","GetBucketPolicy")
| table eventName, userIdentity.userName,
  sourceIPAddress, requestParameters.bucketName,
  awsRegion, eventTime
```

**Expected findings:** Bucket enumeration followed by object downloads

---

## Azure Equivalent (KQL for Microsoft Sentinel)
```kql
AzureActivity
| where OperationName in ("StopLogging", "DeleteTrail")
| project TimeGenerated, OperationName, Caller, CallerIpAddress
```

---

## Notes
- spath required for nested JSON field extraction
- All queries tested against real CloudTrail data
- Sigma source rules in rules/sigma/ folder

## DR-004 — Privilege Escalation Attempt
**MITRE:** T1548 — Privilege Escalation
**Severity:** High

```spl
index="cloudtrail-logs" | spath | search
eventSource="iam.amazonaws.com"
eventName IN ("AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy","CreateUser","AddUserToGroup")
| table eventName, userIdentity.userName, sourceIPAddress,
  requestParameters.userName, requestParameters.policyArn,
  errorCode, eventTime
```

**Note:** errorCode field captures AccessDenied responses —
failed attempts are equally important as successful ones.