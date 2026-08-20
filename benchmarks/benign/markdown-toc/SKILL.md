---
name: markdown-toc
description: Builds a table of contents from Markdown headings.
version: 1.0.0
---

## Usage

Scans headings and outputs a linked contents list.

```javascript
const heads = md.match(/^#+ .+$/gm) || [];
console.log(heads.length + ' headings');
```
