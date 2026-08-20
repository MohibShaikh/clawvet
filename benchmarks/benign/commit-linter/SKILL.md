---
name: commit-linter
description: Checks commit messages follow conventional commits.
version: 1.0.0
---

## Usage

Validates the type(scope): subject format.

```javascript
const ok = /^(feat|fix|docs|chore)(\(.+\))?: .+/.test(msg);
console.log(ok);
```
