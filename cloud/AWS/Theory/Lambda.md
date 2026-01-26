# Lambda

## Basics

- "Severless" compute
- Upload Code → AWS run it
- Event Driven
- Function
- Execution Role
- Triggers
- Enviroment Variables (`may contain juicy files`, check FIRST)

## Pay attention to

- Overly Privileged Execution Role
    - `iam:PassRole`
    - `ec2:*`
    - `s3:*`
    - secretsmanager:GetSecretValue
- Exposed Secrets
    - Env. Variables
    - Source Code
- Writable Functions

## Some tips

- Lambda functions are triggered not only through HTTP requests.
- Lambda execution role define **What the function is allowed to do**
- The following permissions could lead to privilege escalation when assigned to a Lambda's execution role:
    - **`iam:PassRole`**
    - **`ec2:DescribeInstances`**
    - **`s3:ListBucket`**
    - **`lambda:GetFunction`**
