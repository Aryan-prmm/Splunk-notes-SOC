# Splunk SOC Notes

> This repository documents hands-on SOC-style investigations using Splunk on Windows Security Event Logs.

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
- EventCode 4625 (Failed login)

### SPL Query
```spl
index=main EventCode=4625
| stats count by Source_Network_Address
| sort - count
```
### Observation
Multiple failed login attempts were observed originating from the same source network address.

### SOC Analysis
Repeated authentication failures from a single source indicate a potential brute-force attack targeting user accounts.

### Action Taken
- Flag the source network address as suspicious
- Monitor for further authentication attempts
- Recommend blocking the source IP if activity continues

### False Positive Consideration
- User may have repeatedly entered incorrect credentials
- Internal system or script misconfiguration




## Use Case 2: Successful Login After Multiple Failures

### Objective
Detect possible account compromise by correlating failed and successful login attempts.

### Logs Used
- Windows Security Event Logs
- EventCode 4625 (Failed login)
- EventCode 4624 (Successful login)

### SPL Query
```spl
index=main (EventCode=4624 OR EventCode=4625)
| stats count by Source_Network_Address, EventCode
| sort - count
```
### Observation
The same source network address generated multiple failed login attempts followed by a successful login event.

### SOC Analysis
This pattern may indicate that an attacker successfully guessed valid credentials after repeated failed attempts, suggesting a potential account compromise.

### Action Taken
- Flag the source network address as suspicious
- Force password reset for the affected account
- Review recent login activity for lateral movement

### False Positive Consideration
- User may have entered an incorrect password multiple times
- Login attempts may originate from a trusted internal network or VPN

### Analyst Note
Correct time-range selection and field discovery were required. The relevant IP-related field in this environment is `Source_Network_Address`.










