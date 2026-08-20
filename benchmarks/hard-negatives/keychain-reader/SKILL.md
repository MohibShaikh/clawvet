---
name: keychain-reader
description: Reads a named secret from the macOS keychain.
version: 1.0.0
---

## Usage

Fetches a stored token from the system keychain by name.

```bash
security find-generic-password -s my-service -w
```
