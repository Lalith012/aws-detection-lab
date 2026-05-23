# Setup Guide

## Prerequisites
- AWS Account (Free Tier sufficient)
- Python 3.10+
- AWS CLI configured with least privilege IAM user
- Docker (for LocalStack if needed)
- Git

## AWS Configuration

### 1. Create IAM User with Least Privilege
Create an IAM user with only required permissions.
Never use root credentials for programmatic access.

### 2. Configure AWS CLI
```bash
aws configure
# Enter Access Key ID, Secret Access Key
# Region: ap-south-1
# Output: json
```

### 3. Enable GuardDuty
```bash
aws guardduty create-detector --enable
```

### 4. Create CloudTrail
```bash
aws cloudtrail create-trail \
  --name detection-lab-trail \
  --s3-bucket-name your-bucket-name \
  --include-global-service-events \
  --is-multi-region-trail \
  --enable-log-file-validation

aws cloudtrail start-logging --name detection-lab-trail
```

### 5. Enable Security Hub
```bash
aws securityhub enable-security-hub --enable-default-standards
```

## Python Environment
```bash
git clone https://github.com/Lalith012/aws-detection-lab.git
cd aws-detection-lab
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your values
```

## Running Detection Scripts
```bash
# Pull GuardDuty findings
python src/detection_engine/guardduty_findings.py

# Analyze CloudTrail logs
python src/detection_engine/cloudtrail_analyzer.py

# Run detection rules
python src/detection_engine/detection_rules.py

# Build incident timeline
python src/detection_engine/incident_timeline.py
```

## Running Attack Simulations
```bash
# IAM Reconnaissance
python simulations/attack_scenarios/scenario-1-iam-recon/attack.py

# S3 Data Exfiltration
python simulations/attack_scenarios/scenario-2-s3-exfiltration/attack.py

# CloudTrail Disable
python simulations/attack_scenarios/scenario-3-cloudtrail-disable/attack.py
```

## Splunk Setup
1. Install Splunk Enterprise
2. Create index: cloudtrail-logs
3. Run decompress script: python splunk_data/decompress_logs.py
4. Upload decompressed logs to Splunk
5. Run SPL queries from rules/sigma/splunk_queries.md

## Security Notes
- Never commit .env files or CSV credentials
- Always use least privilege IAM policies
- Set billing alarms before creating resources
- Tear down EC2 instances after each session