# MFA Fatigue and Push Bombing — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/14
**MITRE ATT&CK:** T1621, T1556.006
**Reference:** https://attack.mitre.org/techniques/T1621/

---

## Query

```kql
let FailureThreshold = 15;
let TimeWindow = 1h;
let MFAFailures =
    AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode != 0
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | summarize
        FailureCount = count(),
        FirstFailure = min(Timestamp),
        LastFailure = max(Timestamp),
        IPAddresses = make_set(IPAddress)
        by UserPrincipalName, bin(Timestamp, TimeWindow)
    | where FailureCount >= FailureThreshold;
let MFASuccess =
    AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode == 0
    | where AuthenticationRequirement == "multiFactorAuthentication";
MFAFailures
| join kind=inner (MFASuccess) on UserPrincipalName
| where Timestamp1 between (LastFailure .. (LastFailure + TimeWindow))
| project
    UserPrincipalName,
    FailureCount,
    FirstFailure,
    LastFailure,
    SuccessfulAuthTime = Timestamp1,
    IPAddresses
| sort by FailureCount desc
```

---

## Sample Query With Tighter Time Window

The query above uses a one hour window which may generate noise in some environments. The sample below tightens the window to 30 minutes and raises the failure threshold — adjust both values to suit your environment.

```kql
let FailureThreshold = 20;
let TimeWindow = 30m;
let MFAFailures =
    AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode != 0
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | summarize
        FailureCount = count(),
        FirstFailure = min(Timestamp),
        LastFailure = max(Timestamp),
        IPAddresses = make_set(IPAddress)
        by UserPrincipalName, bin(Timestamp, TimeWindow)
    | where FailureCount >= FailureThreshold;
let MFASuccess =
    AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode == 0
    | where AuthenticationRequirement == "multiFactorAuthentication";
MFAFailures
| join kind=inner (MFASuccess) on UserPrincipalName
| where Timestamp1 between (LastFailure .. (LastFailure + TimeWindow))
| project
    UserPrincipalName,
    FailureCount,
    FirstFailure,
    LastFailure,
    SuccessfulAuthTime = Timestamp1,
    IPAddresses
| sort by FailureCount desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Table availability varies by tenant configuration and licensing — run `search * | distinct $table` in Advanced Hunting to confirm which tables are available in your environment before executing these queries
- Requires the `AADSignInEventsBeta` table which is available with Microsoft Defender XDR and appropriate Entra ID licensing
- Organizations using Microsoft Sentinel should replace `AADSignInEventsBeta` with `SigninLogs` and adjust field names accordingly as the schema differs between the two platforms
- `AuthenticationRequirement` is used as a top level field in `AADSignInEventsBeta` — if results are not returned it may need to be extracted from `RawEventData` using `parse_json` similar to how `spath` is used in the Splunk version
- `IPAddress` is used as the IP field in `AADSignInEventsBeta` — this is a top level field in the Advanced Hunting schema and may differ from the `callerIpAddress` field name used in Splunk
- `IPAddresses` collects all unique IP addresses observed across failure events using `make_set()` — baseline against normal user sign-in IP activity to identify anomalous source locations
- `FailureThreshold` is set to 15 in the main query and 20 in the sample query — adjust based on your environment and tolerance for noise — in large organizations a higher threshold may be necessary to reduce volume
- Accounts generating unusually high failure counts should be investigated before being excluded — a real user UPN with thousands of MFA failures may indicate a compromised account, a misconfigured application authenticating as a real user, or a broken SSO or federation loop
- `TimeWindow` is set to 1 hour by default — tighter windows reduce noise but may miss slower more patient push bombing attempts
- Time windowing is intentionally configurable rather than fixed — MFA fatigue attacks can occur rapidly over minutes or more patiently over longer periods, and the right window will vary by environment
- The join logic surfaces only users who had a successful MFA authentication following the failure threshold being reached, reducing false positives significantly
- Results are sorted by failure count descending to surface the most aggressive push bombing attempts first
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting

---

## Related Defender Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Entra ID Protection — Suspicious MFA activity
- Entra ID Protection — Unfamiliar sign-in properties
- Entra ID Protection — Atypical travel
- Entra ID Protection — Impossible travel
- Microsoft Defender for Cloud Apps — Suspicious authentication activity
