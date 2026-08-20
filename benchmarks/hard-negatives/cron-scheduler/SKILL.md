---
name: cron-scheduler
description: Schedules a recurring local backup with cron.
version: 1.0.0
---

## Usage

Adds a crontab entry so your backup runs nightly.

```bash
crontab -l
(crontab -l; echo '0 2 * * * ~/backup.sh') | crontab -
```
