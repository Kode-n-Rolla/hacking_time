# 🚨 **Quick Attack Checklist for Elastic Beanstalk**

1. **Enumerate environments** → `describe-environments`
2. **Extract configurations** → `describe-configuration-settings`
   - Parse **env vars**, IAM roles, EC2 instance types, etc.
3. **Figure out whether you can...**
   - ➕ **Create a new application version**: `CreateApplicationVersion`
   - 🔁 **Update the environment**: `UpdateEnvironment`
   - 📎 **Assume the attached IAM role**
4. **If deployment is possible - you can deploy a malicious app with a backdoor** 😈

---

## ⚠️ What you may find in environment variables:

- `DB_PASSWORD`, `API_KEY`, `SECRET_KEY`
- SMTP credentials
- AWS credentials for other services
- Internal API endpoints

---

If you see:

```json
"OptionName": "ServiceRole",
"Value": "aws-elasticbeanstalk-service-role"
```
Immediately review this role - it may have access to S3, EC2, IAM, or even admin-level permissions.
