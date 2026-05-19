# AWS Detection Engineering & Threat Hunting Lab

![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen)
![AWS](https://img.shields.io/badge/AWS-CloudTrail%20%7C%20GuardDuty%20%7C%20Security%20Hub-orange)
![Python](https://img.shields.io/badge/Python-3.14-blue)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> A hands-on AWS-native detection engineering lab simulating real-world
> cloud attack techniques, building automated detection logic, and
> demonstrating threat hunting across CloudTrail, GuardDuty, and Splunk.

---

## What This Project Demonstrates

- Building a detection pipeline from raw AWS logs to actionable findings
- Simulating real attacker TTPs in a controlled AWS environment
- Writing custom detection rules mapped to MITRE ATT&CK techniques
- Threat hunting using Python automation and Splunk SPL queries
- Centralizing security findings across AWS native services

---

## Architecture

```
Attack Simulation Layer
(Controlled TTPs on owned infrastructure)
        |
        v
AWS CloudTrail  -->  Log Collection & API Activity Monitoring
        |
        v
AWS GuardDuty  -->  Managed Threat Detection & Alerting
        |
        v
AWS Security Hub  -->  Centralized Findings Aggregation
        |
        v
Python Detection Engine  -->  boto3 + Custom Sigma Rules
        |
        v
Splunk  -->  SIEM Visualization & Threat Hunting
```

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic | Detection Status |
|---|---|---|---|
| T1078 | Valid Accounts | Initial Access | 🔄 In Progress |
| T1530 | Data from Cloud Storage | Collection | 🔄 In Progress |
| T1548 | Abuse Elevation Control | Privilege Escalation | 🔄 In Progress |
| T1087 | Account Discovery | Discovery | 🔄 In Progress |
| T1562 | Impair Defenses | Defense Evasion | 🔄 In Progress |

---

## Repository Structure

```
aws-detection-lab/
├── src/
│   ├── detection_engine/     # Core detection logic
│   ├── threat_hunting/       # Hunting scripts and notebooks
│   └── utils/                # Shared utilities
├── rules/
│   ├── sigma/                # Sigma detection rules
│   └── custom/               # Custom AWS-specific rules
├── simulations/
│   └── attack_scenarios/     # Documented attack simulations
├── findings/
│   ├── reports/              # Detection findings reports
│   └── screenshots/          # Evidence screenshots
├── diagrams/                 # Architecture diagrams
├── docs/
│   ├── setup-guide.md        # Environment setup instructions
│   ├── architecture.md       # Detailed architecture decisions
│   ├── attack-scenarios.md   # Attack simulation documentation
│   └── mitre-mapping.md      # Full MITRE ATT&CK mapping
├── tests/                    # Unit tests
├── .env.example              # Environment variable template
├── requirements.txt          # Python dependencies
└── DISCLAIMER.md             # Legal disclaimer
```

---

## Tech Stack

| Category | Technology |
|---|---|
| Cloud Platform | AWS (CloudTrail, GuardDuty, Security Hub, S3, IAM) |
| Detection Engine | Python 3.14, boto3 |
| Detection Rules | Sigma Rules |
| SIEM | Splunk (Free Tier) |
| Infrastructure as Code | Terraform |
| Frameworks | MITRE ATT&CK |
| Version Control | Git, GitHub |

---

## Cross-Cloud Equivalents

| AWS Service | Azure Equivalent | GCP Equivalent |
|---|---|---|
| CloudTrail | Azure Monitor / Activity Logs | Cloud Audit Logs |
| GuardDuty | Microsoft Defender for Cloud | Security Command Center |
| Security Hub | Microsoft Sentinel | Chronicle SIEM |
| IAM | Azure AD / Entra ID | Cloud IAM |
| S3 | Azure Blob Storage | Cloud Storage |

---

## Setup

### Prerequisites
- AWS Account (Free Tier)
- Python 3.10+
- AWS CLI configured
- Docker (for local services)

### Installation

```bash
# Clone the repository
git clone https://github.com/Lalith012/aws-detection-lab.git
cd aws-detection-lab

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Configure environment
copy .env.example .env
# Edit .env with your AWS credentials
```

---

## Project Status

| Phase | Description | Status |
|---|---|---|
| Phase 1 | Repository setup and documentation | ✅ Complete |
| Phase 2 | CloudTrail and GuardDuty configuration | 🔄 In Progress |
| Phase 3 | Attack simulation scenarios | ⏳ Pending |
| Phase 4 | Python detection engine | ⏳ Pending |
| Phase 5 | Sigma rules and Splunk integration | ⏳ Pending |
| Phase 6 | Full documentation and diagrams | ⏳ Pending |

---

## Disclaimer

All techniques demonstrated in this repository were performed exclusively
on infrastructure owned by the author. See [DISCLAIMER.md](DISCLAIMER.md)
for full details.

---

## Author

**Lalith**
Cloud Security Engineer (Transitioning)
[GitHub](https://github.com/Lalith012)
