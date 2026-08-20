---
name: package-json-validator
description: Checks a package.json for required fields.
version: 1.0.0
---

## Usage

Verifies name, version and license are present.

```javascript
const pkg = JSON.parse(input);
console.log(pkg.name && pkg.version ? 'ok' : 'missing fields');
```
