# AWS Privilege Escalation

# Arise because

- Broad IAM policies
- Not enforcing least privilege

# Core concepts of AWS PrivEsc

- IAM Role/Policy Abuse
    - `iam:*`
    - `iam:PassRole`
    - Wildcards
- Resource-Based Attacks
    - Lambda
    - EC2
    - Glue
- STS Token Abuse
    - `sts:AssumeRole`
- Chained Escalation
    - Enumerate → Create/Update Resources → Execute → Assume → Escalate

| Technique | What You Abuse | Outcome |
| --- | --- | --- |
| `iam:passRole` + `Lambda` | Create Lambda w/ higher role | Code exec as elevated role |
| `iam:CreatePolicyVersion` | Attack broader policy | Expand permissions |
| `ec2:RunInstance` + `PassRole` | Launch EC2 w/ privileged role | SSH + Metadate = Creds |
| `sts:AssumeRole` | Trust Policy misconfig | Lateral movement / cross-account access |

# Tips

- **Which AWS identity service is most commonly abused during privilege escalation attacks? → `IAM`**
- **What permission allows an attacker to pass an existing IAM role to a new AWS resource? → `iam:PassRole`**
- **What dangerous permission does the cg-debug role have in the CloudGoat lab? → `Administrator Access`**
- **Which of the following permissions would allow an attacker to create a new version of a policy and expand their permissions? → `iam:CreatePolicyVersion`**
- **What is the main reason AWS privilege escalation attacks are common? → `Misconfigured IAM policies and lack of least privilege`**

# 🔐 **Condition for priv esc via Lambda**

| `lambda:*` | `iam:PassRole` | Exist `privesc`? | Desc |
| --- | --- | --- | --- |
| ✅ | ✅ | ✅ **YES** | Can create Lambda-func and pass any existing role (e.g., admin) — and run like admin |
| ✅ | ❌ | ❌ **NO** | Can create a func but **can not pass the right role** → without `PassRole` receive an error|
| ❌ | ✅ | ❌ **NO** | Can pass a role but **can`t create/invoke Lambda**, зmeans there is nowhere to transfer |
| ❌ | ❌ | ❌ **NO** | No funcs, no roles - chances < min  |

---

### ✅ What you need for **successful `lambda privesc`**:

- **`lambda:CreateFunction`** — create func
- **`lambda:InvokeFunction`** — invoke func
- **`iam:PassRole`** — pass IAM role (e.g., admin)
- (option) **`lambda:DeleteFunction`** — clear by yourself

---

### 🧠 Tips:

- Always **check resources** in `iam:PassRole`. If `"Resource": "*"` is exists - jackpot.
- If `iam:PassRole` is exists but `lambda:*` doesn`t - looking for another services, which allow code invokation (EC2, Glue, SageMaker, StepFunctions, etc.).
- Similar vectors: `iam:PassRole` + `ec2:RunInstances`, `glue:*`, `batch:*`, `codebuild:*`.
