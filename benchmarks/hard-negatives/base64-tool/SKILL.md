---
name: base64-tool
description: Encodes and decodes base64 strings locally.
version: 1.0.0
---

## Usage

A plain base64 utility for the shell and the browser.

```bash
echo hello | base64
echo aGVsbG8= | base64 --decode
```

```javascript
console.log(atob('aGVsbG8='));
```
