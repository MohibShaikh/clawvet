---
name: slug-generator
description: Turns a title into a URL-friendly slug.
version: 1.0.0
---

## Usage

Lowercases, trims, and hyphenates a title.

```javascript
const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, '-');
console.log(slug);
```
