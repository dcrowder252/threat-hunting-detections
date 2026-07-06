# RMM Service Installation — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/04/21
**MITRE ATT&CK:** T1219.002
**Reference:** https://attack.mitre.org/techniques/T1219/002/

---

## Query

```kql
DeviceEvents
| where ActionType == "ServiceInstalled"
| where ServiceName has_any (
    "AnyDesk",
    "TeamViewer",
    "ScreenConnect",
    "Atera Agent",
    "SplashtopRemoteService"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ServiceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

---

## Expanded Version (Service Name + Command Line)

```kql
DeviceEvents
| where ActionType == "ServiceInstalled"
| where ServiceName has_any (
    "AnyDesk",
    "TeamViewer",
    "ScreenConnect",
    "Atera Agent",
    "SplashtopRemoteService"
)
or InitiatingProcessCommandLine has_any (
    "AnyDesk",
    "TeamViewer",
    "ScreenConnect",
    "Atera",
    "Splashtop"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ServiceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Field names may vary across tenants — adjust as necessary for your environment
- `ServiceName` is the typical field for the service name in Microsoft Defender telemetry
- The expanded version also searches `InitiatingProcessCommandLine`, which is useful if an attacker renames the service to something benign
- The `InitiatingProcessCommandLine` terms are intentionally broader — for example `Atera` instead of `Atera Agent` — because command line paths reference folder or binary names rather than friendly display names
- If the `InitiatingProcessCommandLine` match produces too much noise, tighten the strings after baselining legitimate hits in your environment
- This list is not exhaustive — add additional RMM service names as needed
- Review results against your approved RMM tool baseline before alerting
