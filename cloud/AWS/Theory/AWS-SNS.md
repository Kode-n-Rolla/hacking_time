# What Is It?

**SNS (Simple Notification Service)** is a **messaging and notification service**.  
It allows sending messages to:

- 📬 **Email**
- 📱 **SMS**
- ☁️ **HTTP/S endpoints (webhooks)**
- 🔁 **SQS (Simple Queue Service)**
- 🔥 **Lambda functions**

---

# 🤖 How Does It Work?

1. A **topic** is created - essentially a broadcast channel.
2. **Subscribers** attach to the topic: email, HTTP endpoint, queue, etc.
3. Someone calls `Publish`, and SNS delivers the message to all subscribers.

---

# ⚠️ Where Are the Vulnerabilities?

If SNS is **misconfigured**, an attacker may be able to:

- 📩 Subscribe **their own email or webhook** to a topic
- 🕵️ Receive sensitive data from published messages (e.g., logs, flags, tokens)
- 🔄 Abuse the subscription as a feedback channel (e.g., for C2 or SSRF)

# Graphs

## 🔗 Attack Graph - AWS SNS
```
[Compromised IAM User]
          |
          v
[Enumerate SNS Resources]
 (list-topics, list-subscriptions,
  get-topic-attributes)
          |
          v
[Identify Target Topic]
          |
          +--> [Subscribe Attacker Endpoint]
          |        |
          |        v
          |   [Receive Published Messages]
          |        |
          |        v
          |   [Sensitive Data Exposure]
          |
          +--> [Analyze Message Flow]
                    |
                    v
          [Logs / Tokens / Internal Events]
```
💡 What this graph shows:
- SNS acts as a fan-out distribution point for messages.
- With limited permissions, an attacker may:
  - enumerate topics and subscriptions,
  - attach their own endpoint (email/webhook),
  - passively receive all future messages,
  - extract sensitive data from message payloads.

This is especially dangerous when SNS is used for logs, alerts, or internal events.

## ⚠️ Privilege Escalation Graph - SNS + IAM / Lambda
```
[Limited IAM User]
  |  sns:Subscribe
  |  sns:Publish
  |  (optional) iam:PassRole
  v
[Subscribe Lambda / HTTP Endpoint]
          |
          v
[Trigger Message Delivery]
          |
          v
[Code Execution / Data Exfiltration]
          |
          +--> Invoke Lambda
          +--> Trigger Internal HTTP Calls
          +--> SSRF / C2 Channel
```
💥 Key idea:

> SNS can be abused as an event trigger and data exfiltration channel.

If an attacker can:
- subscribe endpoints, or
- publish arbitrary messages,

they can:
- trigger Lambda functions,
- force HTTP callbacks to attacker-controlled servers,
- use SNS as a C2-like communication channel.

## 🧠 Expanded Attack Path (Mental Model)
```
IAM User
  |
  v
SNS Control Plane
  |
  +--> Topics
  +--> Subscriptions
  |
  v
SNS Delivery Layer
  |
  +--> Email / SMS
  +--> HTTP Endpoints
  +--> SQS
  +--> Lambda
```
**Mental model:**

SNS is a bridge between control plane events and external/internal consumers.

Misconfigured SNS:
- leaks internal signals,
- enables passive data collection,
- and creates indirect execution paths.

## 🔍 Indicators of High Risk
```
[ ] sns:Subscribe
[ ] sns:Publish
[ ] Public or overly permissive Topic Policy
[ ] HTTP/S subscriptions
[ ] SNS triggering Lambda functions
```
If 2 or more are present - look for an attack or escalation path.

## 🛡 Defensive Graph (Blue Team View)
```
[SNS Topic]
   |
   +--> Restricted Topic Policy
   |
   +--> Controlled Subscriptions
   |
   +--> No Public Endpoints
   |
   +--> CloudTrail Monitoring
   |
   +--> Message Content Review
```
**🛡 Defensive notes:**
- Restrict `sns:Subscribe` and `sns:Publish`
- Avoid public topic policies
- Carefully review HTTP/S subscriptions
- Monitor SNS activity via CloudTrail
- Never publish secrets or tokens in messages

# 🎯 Why SNS Is Dangerous When Misconfigured

SNS is often treated as “just notifications”, but in reality it is:
- a data distribution hub,
- an event trigger, and
- a potential exfiltration channel.

That makes it a powerful primitive for attackers.


