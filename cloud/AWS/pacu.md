# Modules

- `search` for searching
- `import_keys` → import aws profile
- `data` → check db about current profile
- `iam__enum_users_roles_policies_groups` → basic recon
- `iam__enum_permissions` → recon perms for the current user
- `iam_bruteforce_permissions` → tries all API calls to uncover which ones the current IAM user can perform, revealing a set of `ec2:*` permissions
- `lambda__enum` → lambda enumeration
- `ec2_enum` → EC2 enumeration
- `iam__privesc_scan` - with `--scan-only` scanning for privesc paths with user perms
- enum for `beanstalk` module
- and for `sns`
- `secrets__enum` → Secrets Manager
