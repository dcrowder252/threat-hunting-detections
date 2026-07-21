# Suspicious Device Registration — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/14
**MITRE ATT&CK:** T1098.005
**Reference:** https://attack.mitre.org/techniques/T1098/005/

---

## Query 1 — Failed Device Registration Attempts

Failed device registration attempts may indicate an attacker working through conditional access controls or enrollment restrictions. On its own this activity may represent an attacker who was blocked before successfully registering a device. A threshold is applied to reduce noise from users who fail device enrollment through normal user error.

```kql
let FailureThreshold = 3;
let TimeWindow = 1h;
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "Add device",
    "Register device"
)
| extend EventDetails = parse_json(RawEventData)
| extend ResultStatus = tostring(EventDetails.ResultStatus)
| where ResultStatus != "Success"
| summarize
    FailureCount = count(),
    FirstFailure = min(Timestamp),
    LastFailure = max(Timestamp),
    IPAddresses = make_set(callerIpAddress)
    by AccountUpn, bin(Timestamp, TimeWindow)
| where FailureCount >= FailureThreshold
| sort by FailureCount desc
```

---

## Query 2 — Failed Device Registration Attempts Followed by Success

Accounts that experienced multiple failed device registration attempts followed by a successful registration are a high confidence indicator of malicious device enrollment activity. This pattern suggests an attacker who persisted through access controls and eventually succeeded in registering an attacker-controlled device.

```kql
let FailureThreshold = 3;
let TimeWindow = 1h;
let DeviceFailures =
    CloudAppEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("Add device", "Register device")
    | extend EventDetails = parse_json(RawEventData)
    | extend ResultStatus = tostring(EventDetails.ResultStatus)
    | where ResultStatus != "Success"
    | summarize
        FailureCount = count(),
        FirstFailure = min(Timestamp),
        LastFailure = max(Timestamp),
        IPAddresses = make_set(callerIpAddress)
        by AccountUpn, bin(Timestamp, TimeWindow)
    | where FailureCount >= FailureThreshold;
let DeviceSuccess =
    CloudAppEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("Add device", "Register device")
    | extend EventDetails = parse_json(RawEventData)
    | extend ResultStatus = tostring(EventDetails.ResultStatus)
    | where ResultStatus == "Success";
DeviceFailures
| join kind=inner (DeviceSuccess) on AccountUpn
| where Timestamp1 between (LastFailure .. (LastFailure + TimeWindow))
| project
    AccountUpn,
    FailureCount,
    FirstFailure,
    LastFailure,
    SuccessfulRegistrationTime = Timestamp1,
    IPAddresses
| sort by FailureCount desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Table availability varies by tenant configuration and licensing — run `search * | distinct $table` in Advanced Hunting to confirm which tables are available in your environment before executing these queries
- Requires the `CloudAppEvents` table which is available with Microsoft Defender for Cloud Apps licensing
- Organizations using Microsoft Sentinel should use the `AuditLogs` table and adjust field names accordingly
- `callerIpAddress` is an already extracted field — not always populated as operations initiated by a service or automated process may not include an IP address — empty values are expected and do not indicate a query error
- `make_set(callerIpAddress)` collects all unique IP addresses observed across failure events for the same user — useful for identifying multiple source IPs indicating a distributed attack
- `FailureThreshold` is set to 3 by default — lower than the MFA fatigue threshold since repeated device registration failures are less common in normal administrative activity
- `TimeWindow` is set to 1 hour in both queries — adjust based on your environment and tolerance for noise
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting

---

## Related Defender Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Entra ID Protection — Anomalous device registration
- Entra ID Protection — Unfamiliar sign-in properties
- Entra ID Protection — Impossible travel

**MFA Fatigue as a Precursor**

MFA fatigue activity detected prior to a device registration attempt is a strong indicator that the device registration is malicious. An attacker who successfully bypassed MFA through push bombing may immediately attempt to register a device to satisfy conditional access requirements and establish persistent trusted access. Correlating MFA fatigue alerts with device registration activity for the same account and timeframe should be treated as a critical priority for investigation.
