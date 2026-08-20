---
name: regex-tester
description: Tests a regular expression against sample input.
version: 1.0.0
---

## Usage

Provide a pattern and text to see the matches.

```javascript
const re = new RegExp(pattern, 'g');
console.log([...text.matchAll(re)]);
```
