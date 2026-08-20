---
name: timezone-helper
description: Converts a time between two timezones.
version: 1.0.0
---

## Usage

Give a time and two zones to see the offset.

```javascript
const d = new Date(iso);
console.log(d.toLocaleString('en-US', { timeZone: zone }));
```
