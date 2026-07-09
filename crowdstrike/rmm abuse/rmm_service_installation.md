# RMM Service Installation — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/04/21
**MITRE ATT&CK:** T1219.002
**Reference:** https://attack.mitre.org/techniques/T1219/002/

---

## Query

```kusto
#event_simpleName=CreateService
| ServiceDisplayName = /AnyDesk|TeamViewer|ScreenConnect|Atera Agent|SplashtopRemoteService/i
| table(@timestamp, ComputerName, UserName, ServiceDisplayName, ServiceImagePath)
| sort(field=@timestamp, order=desc)
```

---

## Expanded Version (Display Name + Image Path)

```kusto
#event_simpleName=CreateService
| ServiceDisplayName = /AnyDesk|TeamViewer|ScreenConnect|Atera Agent|SplashtopRemoteService/i
OR ServiceImagePath = /AnyDesk|TeamViewer|ScreenConnect|Atera|Splashtop/i
| table(@timestamp, ComputerName, UserName, ServiceDisplayName, ServiceImagePath)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `CreateService` is used as the event name and was validated in testing — some tenants may surface this activity under `ServiceInstalled` instead, so adjust the event name as necessary for your environment
- Field names may vary across tenants — adjust as necessary for your environment
- `ServiceDisplayName` is the typical field for the service name in CrowdStrike telemetry
- The expanded version also searches `ServiceImagePath`, which is useful if an attacker renames the service display name to something benign
- The `ServiceImagePath` terms are intentionally broader — for example `Atera` instead of `Atera Agent` — because image paths reference folder or binary names rather than friendly display names
- If the `ServiceImagePath` match produces too much noise, tighten the strings after baselining legitimate hits in your environment
- This list is not exhaustive — add additional RMM service names as needed
- Review results against your approved RMM tool baseline before alerting
