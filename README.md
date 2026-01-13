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

## Use Case 3: Login Outside Business Hours

### Objective
Detect potentially suspicious login activity occurring outside normal business hours.

### Logs Used
- Windows Security Event Logs
- EventCode 4624 (Successful login)

### SPL Query
```spl
index=main EventCode=4624
| eval hour=strftime(_time,"%H")
| where hour < 8 OR hour > 19
| table _time hour AccountName Source_Network_Address
```
### Observation
Successful login events were observed during late night or early morning hours.

### SOC Analysis
Logins outside business hours may indicate compromised credentials or unauthorized access, especially for non-administrative users.

### Action Taken
- Verify login activity with the user
- Check user role and geolocation
- Escalate if activity is abnormal

### False Positive Consideration
- Administrators working after hours
- Scheduled maintenance or batch jobs

## Use Case 4: Account Lockout Detection

### Objective
Detect account lockout events caused by repeated failed login attempts.

### Logs Used
- Windows Security Event Logs
- EventCode 4740 (Account locked out)
- EventCode 4625 (Failed login)

### SPL Query
```spl
index=main (EventCode=4625 OR EventCode=4740)
| table _time EventCode AccountName Source_Network_Address
```

### Observation
Multiple failed login attempts were observed for an account followed by an account lockout event.

### SOC Analysis
An account lockout after repeated authentication failures strongly indicates a brute-force attack attempt and increases the confidence level of malicious activity.

### Action Taken
- Notify user and IT support
- Unlock or reset the affected account
- Block or monitor the source network address

### False Positive Consideration
- User repeatedly entered incorrect credentials
- Misconfigured application or service using old credentials














