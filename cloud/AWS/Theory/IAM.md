# Identity and Access Management (IAM)
**What user can do and what note!**

## Core

- **Users** → They have **long-term credentials** like usernames, passwords, and access keys
- **Groups** → Are just a way to manage permissions for multiple users at once
- **Policies** → define what a user, group, or role can and can’t do. They’re written in JSON and attached to IAM entities. There are two kinds:
    - **Managed Policies** – Reusable across users and groups. These are easier to manage and scale.
    - **Inline Policies** – Attached directly to one user or group. These are harder to track and often the source of privilege escalation bugs in real-world environments
- **Roles →** Are like users but without long-term credentials. You assume a role temporarily, and AWS gives you credentials that expire after a set time. For example, if I’m a security analyst investigating an incident, I might assume a role that gives me access to logs for a few hours and then loses access when I’m done. Roles help enforce the principle of least privilege.

## Test for …

- **Privilege Escalation.** Can I go from a low-privilege user to an admin? This is the most common and most impactful finding in cloud environments.
- **Lateral Movement.** Even if I can’t get admin access, can I move sideways into another user, role, or resource with sensitive access—like an S3 bucket full of data?
- **Data Exfiltration.** Can I take over a Lambda function and send data to my own server?
- **Persistence.** If I can create access keys for another user, I can quietly backdoor their account without changing their password. That kind of access is hard to detect unless you’ve got solid logging and alerting in place.

## **What to Watch For …**

1. **Users with excessive permissions**
2. **Roles that can be assumed**
3. **Policies that use wildcards** (e.g., `"Action": "*"` or `"Resource": "*"`)
4. **Services or Lambda functions with elevated permissions** that you can potentially abuse
