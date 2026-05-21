# Windows Security Event Log Cleared — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/08
**MITRE ATT&CK:** T1070.001
**Reference:** https://attack.mitre.org/techniques/T1070/001/

---

## Query

```kql
DeviceEvents
| where ActionType == "SecurityLogCleared"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- `SecurityLogCleared` is the ActionType generated when the Windows Security audit log is cleared
- `InitiatingProcessAccountName` and `InitiatingProcessAccountDomain` identify the account responsible for clearing the log
- Any occurrence outside of an approved maintenance window should be investigated immediately
- Field names may vary across tenants — adjust as necessary for your environment
