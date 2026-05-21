# Windows Event Log Cleared — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/21
**MITRE ATT&CK:** T1070.001
**Reference:** https://attack.mitre.org/techniques/T1070/001/

---

## Query

```kql
DeviceEvents
| where ActionType == "EventLogCleared"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, AdditionalFields
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- `EventLogCleared` is the ActionType generated when any Windows Event Log is cleared
- `AdditionalFields` may contain the name of the specific log that was cleared and is an important triage field
- `InitiatingProcessAccountName` and `InitiatingProcessAccountDomain` identify the account responsible for clearing the log
- Any occurrence outside of an approved maintenance window should be investigated immediately
- Field names may vary across tenants — adjust as necessary for your environment
