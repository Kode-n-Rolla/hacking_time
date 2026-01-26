# 1. Get list apps:

```bash
aws elasticbeanstalk describe-applications --profile [profile_name]
```

# 2. Get env:

```bash
aws elasticbeanstalk describe-environments --profile [profile_name]
```

# 3. Get config settings (creds are often here!):

```bash
aws elasticbeanstalk describe-configuration-settings \
  --application-name <app_name> \
  --environment-name <env_name> \
  --profile <prof>
```

# 4. Get EC2 with env

```bash
aws elasticbeanstalk describe-environment-resources \
  --environment-name <env_name> \
  --profile <prof>
```

(usefull here is `EnvironmentTier`, `Instances`, `LoadBalancers`, `AutoScalingGroups`)
