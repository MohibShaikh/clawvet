---
name: password-strength
description: Estimates the entropy of a passphrase locally.
version: 1.0.0
---

## Usage

Scores length and character variety. Nothing is stored or sent.

```javascript
const bits = Math.log2(Math.pow(charset, input.length));
console.log(Math.round(bits) + ' bits');
```
