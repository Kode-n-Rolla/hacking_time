# 1. List subsubers

```bash
aws sns list-topics --profile sns_start
```

# 2. Get attributes

```bash
aws sns get-topic-attributes --topic-arn <ARN> --profile sns_start
```

Ищи что-то вроде:

- **HTTP(S) endpoint**, куда отправляются сообщения.
- Lambda
- Email

# 3. List subscrubers

```bash
aws sns list-subscriptions-by-topic --topic-arn <ARN> --profile sns_start
```
