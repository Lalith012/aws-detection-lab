# Architecture Decisions

## Overview
This lab implements a multi-layer AWS-native security detection pipeline
combining managed AWS services with custom Python tooling and industry
standard detection frameworks.

## Layer 1 — Attack Simulation
Controlled attack simulations performed on owned infrastructure using
Python scripts mapped to MITRE ATT&CK techniques. All simulations
include setup, execution, detection, and remediation phases.

## Layer 2 — Log Collection
AWS CloudTrail configured with:
- Multi-region trail coverage
- Log file validation enabled
- S3 bucket with explicit CloudTrail write policy
- Global service events included for IAM coverage

**Design decision:** Multi-region trail chosen over single-region to
ensure no API calls are missed regardless of which region they originate
from. Log file validation adds cryptographic integrity proof.

## Layer 3 — Managed Detection
AWS GuardDuty provides baseline threat detection using AWS threat
intelligence. Key findings in this lab:
- RootCredentialUsage — T1078.004
- CloudTrailLoggingDisabled — T1562.008

**Design decision:** GuardDuty complements custom detection rather than
replacing it. Managed detection covers known threat patterns while
custom rules cover environment-specific scenarios.

## Layer 4 — Custom Detection Engine
Three-component Python detection pipeline:
- CloudTrail Analyzer — parses raw S3 logs, applies suspicious API lookup
- Detection Rule Engine — structured rules with severity/confidence scoring
- Incident Timeline Builder — chronological attack narrative generation

**Design decision:** Data-driven rule design allows adding new detection
rules without code changes. Risk scoring uses weighted severity and
confidence multipliers to prevent alert fatigue.

## Layer 5 — SIEM Integration
Splunk ingests CloudTrail logs via NDJSON format. Sigma rules provide
vendor-agnostic detection logic converted to SPL using sigma-cli.

**Design decision:** Sigma rules chosen over native SPL for portability.
Same rules convert to Microsoft Sentinel KQL or Elastic DSL without
rewriting detection logic.

## Cross-Cloud Mapping
| AWS Service | Azure Equivalent | GCP Equivalent |
|---|---|---|
| CloudTrail | Azure Monitor Activity Logs | Cloud Audit Logs |
| GuardDuty | Microsoft Defender for Cloud | Security Command Center |
| Security Hub | Microsoft Sentinel | Chronicle SIEM |
| IAM | Azure AD / Entra ID | Cloud IAM |
| S3 | Azure Blob Storage | Cloud Storage |