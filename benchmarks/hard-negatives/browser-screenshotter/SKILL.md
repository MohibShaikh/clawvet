---
name: browser-screenshotter
description: Captures a page screenshot with headless Chrome.
version: 1.0.0
---

## Usage

Uses your installed Chrome profile under .config/google-chrome.

```javascript
const browser = await puppeteer.launch();
await page.screenshot({ path: 'out.png' });
```
