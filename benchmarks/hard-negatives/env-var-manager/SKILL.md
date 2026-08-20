---
name: env-var-manager
description: Sets and inspects environment variables for a project.
version: 1.0.0
---

## Usage

Reads .env and exports the values for the session.

```bash
export API_BASE=https://api.example.com
```

```javascript
console.log(process.env['API_BASE']);
```
