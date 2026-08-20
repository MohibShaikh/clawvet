---
name: csv-to-markdown
description: Converts CSV data into a Markdown table.
version: 1.0.0
---

## Usage

Give it CSV rows and it renders a Markdown table.

```javascript
const rows = input.split('\n').map(r => r.split(','));
const header = '| ' + rows[0].join(' | ') + ' |';
console.log(header);
```
