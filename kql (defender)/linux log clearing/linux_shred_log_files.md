# Linux Shred Command Used Against Log Files — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/25
**MITRE ATT&CK:** T1070.002, T1070.003
**Reference:** https://attack.mitre.org/techniques/T1070/002/

---

## Query

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where FileName == "shred"
| where ProcessCommandLine has_any (
    "/var/log/",
    ".bash_history"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- The `DeviceInfo` subquery filters results to Linux endpoints only
- The query is scoped to shred activity targeting log files and bash history files specifically to reduce noise from legitimate use of shred against other files
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Shred used against log files or history files has very few legitimate explanations and should be treated as high priority when detected
- MDE Linux coverage requires Microsoft Defender for Endpoint to be deployed on Linux endpoints
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
