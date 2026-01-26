# **Confirm AWS Identity ("Whoami")**

This command returns your account ID, IAM user ID, and ARN.

```bash
aws sts get-caller-identity --profile [profile_name]
```

# Profiles

```bash
cat ~/.aws/config
```

# Creds

```bash
cat ~/.aws/credentials
```

if has a session_token, add to profile

```bash
[cg-ec2]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
aws_session_token = YOUR_SESSION_TOKEN
```

# Reconfig profile

```bash
aws configure --profile [profile_name]
```

# **Enabling Autocomplete for the AWS CLI**

## **Kali Linux Install Instructions**

### **Step 1: Run this command to modify your ~/.zshrc file.**

`echo -e '\nexport PATH=/usr/local/bin/:$PATH\nautoload bashcompinit && bashcompinit\nautoload -Uz compinit && compinit\ncomplete -C "/usr/local/bin/aws_completer" aws' >> ~/.zshrc`

### **Step 2: Reload the profile `source ~/.zshrc`**

### **Step 3: Verify command completion. You can do this by typing a partial command and pressing Tab to see available commands.`aws s[Press Tab]`**

![](https://uploads.teachablecdn.com/attachments/zNpi7qhwTC2DMWi3yGtA_2025-05-07_20-20_1.png)
