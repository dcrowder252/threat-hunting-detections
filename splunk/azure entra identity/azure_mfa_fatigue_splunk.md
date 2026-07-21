# MFA Fatigue and Push Bombing — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/17
**MITRE ATT&CK:** T1621, T1556.006
**Reference:** https://attack.mitre.org/techniques/T1621/

---

## Query

```spl
index=<your_index> sourcetype=<your_sourcetype>
| spath path=properties.authenticationRequirement output=authenticationRequirement
| search authenticationRequirement="multiFactorAuthentication"
resultSignature="FAILURE"
| bucket _time span=1h
| stats
    count as FailureCount,
    min(_time) as FirstFailure,
    max(_time) as LastFailure,
    values(callerIpAddress) as IPAddress
    by user, _time
| where FailureCount >= 15
| join type=inner user
    [search index=<your_index> sourcetype=<your_sourcetype>
    | spath path=properties.authenticationRequirement output=authenticationRequirement
    | search authenticationRequirement="multiFactorAuthentication"
    resultSignature="SUCCESS"
    | stats min(_time) as SuccessTime by user]
| where SuccessTime > LastFailure
| eval FirstFailure=strftime(FirstFailure, "%Y-%m-%d %H:%M:%S")
| eval LastFailure=strftime(LastFailure, "%Y-%m-%d %H:%M:%S")
| eval SuccessTime=strftime(SuccessTime, "%Y-%m-%d %H:%M:%S")
| table user, FailureCount, FirstFailure, LastFailure, SuccessTime, IPAddress
| sort - FailureCount
```

---

## Sample Query With Tighter Time Window

The query above uses a one hour window. The sample below tightens the window to 30 minutes and raises the failure threshold — adjust both values to suit your environment.

```spl
index=<your_index> sourcetype=<your_sourcetype>
| spath path=properties.authenticationRequirement output=authenticationRequirement
| search authenticationRequirement="multiFactorAuthentication"
resultSignature="FAILURE"
| bucket _time span=30m
| stats
    count as FailureCount,
    min(_time) as FirstFailure,
    max(_time) as LastFailure,
    values(callerIpAddress) as IPAddress
    by user, _time
| where FailureCount >= 20
| join type=inner user
    [search index=<your_index> sourcetype=<your_sourcetype>
    | spath path=properties.authenticationRequirement output=authenticationRequirement
    | search authenticationRequirement="multiFactorAuthentication"
    resultSignature="SUCCESS"
    | stats min(_time) as SuccessTime by user]
| where SuccessTime > LastFailure
| eval FirstFailure=strftime(FirstFailure, "%Y-%m-%d %H:%M:%S")
| eval LastFailure=strftime(LastFailure, "%Y-%m-%d %H:%M:%S")
| eval SuccessTime=strftime(SuccessTime, "%Y-%m-%d %H:%M:%S")
| table user, FailureCount, FirstFailure, LastFailure, SuccessTime, IPAddress
| sort - FailureCount
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- `authenticationRequirement` is nested in the JSON — `spath` is used to extract it from `properties.authenticationRequirement`
- The nested JSON structure may not be present in all tenants depending on how Azure AD logs are ingested and normalized — some ingestion methods flatten these fields at index time
- `resultSignature` contains the actual authentication result — values are `SUCCESS` and `FAILURE` — the `status` field maps to failure only and should not be used for this detection
- `callerIpAddress` is an already extracted field containing the IP address of the sign-in request
- `callerIpAddress` can be an important data point during triage — baseline the IP addresses normally associated with a user's sign-in activity and investigate any MFA fatigue events originating from IP addresses outside of that expected baseline
- `strftime` is used to convert epoch timestamps to human readable format — adjust the format string as needed for your preference
- The failure threshold is set to 15 by default in the main query and 20 in the sample query — adjust based on your environment and tolerance for noise — in large organizations a higher threshold may be necessary to reduce volume
- Accounts generating unusually high failure counts should be investigated before being excluded — a real user UPN with thousands of MFA failures may indicate a compromised account, a misconfigured application authenticating as a real user, or a broken SSO or federation loop — exclusions should only be made after the activity has been reviewed and confirmed as legitimate
- Time windowing is intentionally configurable — MFA fatigue attacks can occur rapidly over minutes or more patiently over longer periods and the right window will vary by environment
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting

---

## Related Defender Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Entra ID Protection — Suspicious MFA activity
- Entra ID Protection — Unfamiliar sign-in properties
- Entra ID Protection — Atypical travel
- Entra ID Protection — Impossible travel
- Microsoft Defender for Cloud Apps — Suspicious authentication activity
