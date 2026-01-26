# **1. List IAM Users**

### a. List users

```bash
aws iam list-users
```

### b. **Get Info on Your IAM User**

This pulls detailed metadata about the current user.

```bash
aws iam get-user --profile [profile_name]
```

### **c. List All IAM Users in the Account**

This helps identify other users to investigate.

```bash
aws iam list-users --profile [profile_name]
```

### d. **Check Access Keys for Current User**

To check how many access keys are active for your user (max 2 per IAM user):

```bash
aws iam list-access-keys --profile [profile_name] {--user-name [user_name]}
```

---

# **2. Get User Permissions**

### **a. List attached managed policies**

```bash
aws iam list-attached-user-policies --user-name [user-name]
```

### **b. List inline policies**

```bash
aws iam list-user-policies --user-name [user-name]
```

### **c. Get inline policy details**

```bash
aws iam get-user-policy --user-name [user-name] --policy-name [policy-name]
```

---

# **3. List IAM Groups and Permissions**

### **a. List groups for a user**

```bash
aws iam aws --user-name [user-name]
```

### **b. List group policies**

```bash
aws iam list-attached-group-policies --group-name [group-name]
aws iam list-group-policies --group-name [group-name]
```

### **c. Get inline group policy details**

If you identified a policy (e.g., `iam-Enumeration-devs-policy`), retrieve the full JSON policy document:

```bash
aws iam get-group-policy --group-name [group-name] --policy-name [policy-name]
```

Look for wildcard actions, sensitive services like `iam:*`, `s3:*`, `ec2:*`, or privilege escalation paths like `iam:PassRole`

### d. **List All IAM Groups**

This command shows all defined IAM groups in the account.

```bash
aws iam list-groups --profile [profile_name]
```

**Look for group names like:** `iam-Enumeration-Developers`, `iam-Enumeration-Admins`, etc.

### **e. Get Group Details**

Now retrieve more detailed metadata and members for a specific group:

```bash
aws iam get-group \
  --group-name [group_name] \
  --profile [profile_name]
```

**What to look for:**

- List of users in the group
- Group path, creation date, etc.

---

# **4. List IAM Roles and Permissions**

### **a. List all roles**

```bash
aws iam list-roles
```

### **b. Get role details (trust policy)**

```bash
aws iam get-role --role-name [role-name]
```

### **c. List attached policies**

```bash
aws iam list-attached-role-policies --role-name [role-name]
```

### **d. List inline policies**

```bash
aws iam list-role-policies --role-name [role-name]
```

### **e. Get inline role policy details**

```bash
aws iam get-role-policy --role-name [role-name] --policy-name [policy-name]
```

### f. **Narrow Role Results to a Specific Name**

Use a JMESPath query to target a known role (e.g., `SupportRole`):

```bash
aws iam list-roles \
  --query "Roles[?RoleName=='SupportRole']" \
  --profile [profile_name]
```

This filters the output and makes it easier to focus on one role.

### g. Assume role

```bash
aws sts assume-role --role-arn arn:aws:iam::<account>:role/<RoleName> --role-session-name test --profile [profile_name]
```

---

# **5. Get and Decode Policy Documents**

### a. Check Policy Versions

```bash
aws iam list-policy-versions --policy-arn [Policy_ARN] --profile [Profile_name]
```

example of `--policy-arn` value →

 `arn:aws:iam::495599734872:policy/cg-chris-policy-cgid5lvhse6w92`

U need paste the whole string

### **b. Get a managed policy document (by ARN or name)**

```bash
aws iam get-policy --policy-arn [policy-arn]
aws iam get-policy-version --policy-arn [policy-arn] --version-id [version-id]
```

---

# **6. View Full IAM Snapshot**

### **a. Dump all IAM permissions (users, roles, groups, policies)**

```bash
aws iam get-account-authorization-details
```

> Use this to build a full IAM permissions map. Add `--filter` to target roles/users/groups specifically.
> 

# 7. Create access key (if `iam:CreateAccessKey`)

```bash
aws iam create-access-key --user-name [cgidpdea2i4554_admin_user] --profile [profile_name]
```
