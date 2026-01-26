# 1. List APIs

```bash
aws apigateway get-rest-apis --profile sns_start
```

Save that `id`, it's your `API-ID`.

# 2. Get Stages (like `prod`, `dev`, etc.)

```bash
aws apigateway get-stages --rest-api-id a1b2c3d4e5 --profile sns_start
```

To `--rest-api-id` paste `id` from prev step

# 3. Enumerate Resources (aka paths like `/login`, `/secrets`)

```bash
aws apigateway get-resources --rest-api-id a1b2c3d4e5 --profile sns_start
```

Search endpoints

And `curl` with api key to `https://m17c3vrydc.execute-api.us-east-1.amazonaws.com/[from_get-stages]/[found_endpoint]` and `-H "x-api-key: [key]"`
