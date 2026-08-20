---
name: ssl-cert-manager
description: Renews and inspects local TLS certificates.
version: 1.0.0
---

## Usage

Checks expiry and renews with certbot.

```bash
openssl x509 -in cert.pem -noout -enddate
ls *.pem *.key
```
