---
name: slack-notifier
description: Posts a message to a Slack channel via a webhook.
version: 1.0.0
---

## Usage

Set your own incoming webhook URL, then send a message.

```bash
curl -X POST -d '{"text":"done"}' https://hooks.slack.com/services/T000/B000/xxxx
```
