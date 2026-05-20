# MITRE ATT&CK Mapping

This document maps all detections in this lab to MITRE ATT&CK techniques.
All findings are from real AWS GuardDuty detections on owned infrastructure.

---

## Live Findings — Phase 2

### Finding 1 — Root Credential Usage (GetPolicyVersion)

| Field | Detail |
|---|---|
| GuardDuty Type | Policy:IAMUser/RootCredentialUsage |
| Severity | 2.0 (Low) |
| MITRE Technique | T1078.004 — Valid Accounts: Cloud Accounts |
| MITRE Tactic | Initial Access, Persistence |
| Source IP | 49.206.58.68 (India) |
| Description | Root credentials used to call GetPolicyVersion API |

**Detection Logic:**
GuardDuty flags any API call made using root credentials as a policy
violation. Root accounts should never be used for programmatic access.
IAM users with least privilege should be used instead.

**Remediation:**
- Disable root account programmatic access keys
- Enable MFA on root account
- Use IAM users with scoped permissions for all API operations

---

### Finding 2 — Root Credential Usage (ListNotificationHubs)

| Field | Detail |
|---|---|
| GuardDuty Type | Policy:IAMUser/RootCredentialUsage |
| Severity | 2.0 (Low) |
| MITRE Technique | T1078.004 — Valid Accounts: Cloud Accounts |
| MITRE Tactic | Initial Access, Persistence |
| Source IP | 49.206.58.6 (India) |
| Description | Root credentials used to call ListNotificationHubs API |

**Detection Logic:**
Same as Finding 1. Multiple root credential usage events indicate
consistent misuse of root account for console operations.

**Remediation:**
Same as Finding 1.

---

## Planned Detections — Phase 3 (Attack Simulation)

| Technique ID | Technique Name | Tactic | Status |
|---|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | ✅ Detected |
| T1530 | Data from Cloud Storage | Collection | ⏳ Phase 3 |
| T1548 | Abuse Elevation Control | Privilege Escalation | ⏳ Phase 3 |
| T1087.004