# Splunk SOC Notes

This repository contains hands-on SOC-style use cases performed using Splunk.
All queries are executed on real logs with analyst observations and conclusions.
---

## Environment
- SIEM: Splunk Enterprise (Free)
- OS: Windows
- Logs Used: Windows Security Event Logs
---

## Use Case 1: Brute Force Login Detection

### Objective
Detect possible brute-force login attempts using Windows Security logs.

### Logs Used
- Windows Security Event Logs
- EventCode: 4625 (Failed login)

### SPL Query
```spl
index=main EventCode=4625
| stats count by IpAddress
| sort - count


