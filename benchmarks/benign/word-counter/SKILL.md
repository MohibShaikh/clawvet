---
name: word-counter
description: Counts words and estimates reading time.
version: 1.0.0
---

## Usage

Reports word count and minutes to read.

```javascript
const n = text.trim().split(/\s+/).length;
console.log(n, Math.ceil(n / 200) + ' min');
```
