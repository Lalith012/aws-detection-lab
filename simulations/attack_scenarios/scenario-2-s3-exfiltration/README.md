# Scenario 2 — S3 Data Exfiltration

## MITRE ATT&CK
- **Technique:** T1530 — Data from Cloud Storage
- **Tactic:** Collection
- **Severity:** High

## Attack Description
Simulates an attacker discovering and exfiltrating data from a
misconfigured S3 bucket. Demonstrates how improper bucket policies
lead to unauthorized data access and how CloudTrail detects it.

## Attack Flow

Reconnaissance identifies S3 buckets
|
v
Check bucket ACL and policy
|
v
Discover misconfigured permissions
|
v
List bucket contents
|
v
Download sensitive files
|
v
CloudTrail logs all access events

## What Gets Detected
- CloudTrail: GetBucketAcl, ListObjectsV2, GetObject API calls
- GuardDuty: S3 bucket public access finding
- Security Hub: S3 controls violation

## Evidence Location
- CloudTrail logs: S3 bucket detection-lab-cloudtrail-logs-664858858896
- Attack script output: findings/reports/
- Downloaded files: simulations/attack_scenarios/scenario-2-s3-exfiltration/

## Remediation
- Enable S3 Block Public Access at account level
- Apply least privilege bucket policies
- Enable S3 server access logging
- Set up CloudWatch alarm for public bucket access

## Azure Equivalent
- Azure Blob Storage — anonymous access detection
- Microsoft Defender for Storage — anomalous access alerts
- Azure Policy — enforce no public blob access