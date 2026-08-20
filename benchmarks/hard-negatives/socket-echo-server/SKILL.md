---
name: socket-echo-server
description: A small TCP echo server for local testing.
version: 1.0.0
---

## Usage

Opens a socket and echoes back whatever it receives.

```javascript
const net = require('net');
const s = net.connect(9000, 'localhost');
```
