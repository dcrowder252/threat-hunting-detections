# Suspicious Device Registration — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/17
**MITRE ATT&CK:** T1098.005
**Reference:** https://attack.mitre.org/techniques/T1098/005/

---

## Query 1 — Failed Device Registration Attempts

Failed device registration attempts may indicate an attacker working through conditional access controls or enrollment restrictions. A threshold is applied to reduce noise from users who fail device enrollment through normal user error.

```spl
index=<your_index> sourcetype="azure:monitor:aad"
(operationName="Add device" OR operationName="Register device")
status!="success"
| bucket _time span=1h
| stats
    count as FailureCount,
    min(_time) as FirstFailure,
    max(_time) as LastFailure,
    values(callerIpAddress) as IPAddress
    by user, resultDescription, _time
| where FailureCount >= 3
| eval FirstFailure=strftime(FirstFailure, "%Y-%m-%d %H:%M:%S")
| eval LastFailure=strftime(LastFailure, "%Y-%m-%d %H:%M:%S")
| table user, FailureCount, FirstFailure, LastFailure, IPAddress, resultDescription
| sort - FailureCount
```

---

## Query 2 — Failed Device Registration Attempts Followed by Success

Accounts that experienced multiple failed device registration attempts followed by a successful registration are a high confidence indicator of malicious device enrollment activity.

```spl
index=<your_index> sourcetype="azure:monitor:aad"
(operationName="Add device" OR operationName="Register device")
status!="success"
| bucket _time span=1h
| stats
    count as FailureCount,
    min(_time) as FirstFailure,
    max(_time) as LastFailure,
    values(callerIpAddress) as IPAddress
    by user, resultDescription, _time
| where FailureCount >= 3
| join type=inner user
    [search index=<your_index> sourcetype="azure:monitor:aad"
    (operationName="Add device" OR operationName="Register device")
    status="success"
    | stats min(_time) as SuccessTime by user]
| where SuccessTime > LastFailure
| eval FirstFailure=strftime(FirstFailure, "%Y-%m-%d %H:%M:%S")
| eval LastFailure=strftime(LastFailure, "%Y-%m-%d %H:%M:%S")
| eval SuccessTime=strftime(SuccessTime, "%Y-%m-%d %H:%M:%S")
| table user, FailureCount, FirstFailure, LastFailure, SuccessTime, IPAddress, resultDescription
| sort - FailureCount
```

---

## Notes

- Adjust index value to match your environment
- Sourcetype validated as `azure:monitor:aad` — adjust if your environment uses a different sourcetype for Azure AD audit logs
- `operationName` is lowercase — field names in Azure AD logs are case sensitive in Splunk
- `status` is lowercase — `success` is lowercase
- `user` contains the UPN of the account attempting the device registration
- `callerIpAddress` is an already extracted field containing the IP address of the initiating request — not always populated as operations initiated by a service or automated process may not include an IP address — empty values are expected and do not indicate a query error
- `values(callerIpAddress)` collects all IP addresses observed across the failure events for the same user — useful for identifying multiple source IPs indicating a distributed attack
- `strftime` is used to convert epoch timestamps to human readable format — adjust the format string as needed for your preference
- `resultDescription` provides additional context on why a device registration failed — useful for triage
- The failure threshold is set to 3 by default — lower than the MFA fatigue threshold since repeated device registration failures are less common in normal administrative activity
- Time windowing is set to 1 hour in both queries — adjust based on your environment and tolerance for noise
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting

---

## Related Defender Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Entra ID Protection — Anomalous device registration
- Entra ID Protection — Unfamiliar sign-in properties
- Entra ID Protection — Impossible travel

**MFA Fatigue as a Precursor**

MFA fatigue activity detected prior to a device registration attempt is a strong indicator that the device registration is malicious. An attacker who successfully bypassed MFA through push bombing may immediately attempt to register a device to satisfy conditional access requirements and establish persistent trusted access. Correlating MFA fatigue alerts with device registration activity for the same account and timeframe should be treated as a critical priority for investigation.
