# Wevtutil Used to Clear Windows Event Logs — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/21
**MITRE ATT&CK:** T1070.001
**Reference:** https://attack.mitre.org/techniques/T1070/001/

---

## Query

```kql
DeviceProcessEvents
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has_any (
    " cl ",
    " clear-log "
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- `cl` and `clear-log` are the two wevtutil arguments used to clear event logs
- Spaces surrounding the arguments are intentional to avoid partial string matches on other wevtutil commands
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Review the parent process to understand what invoked wevtutil — scripted or automated invocation is a strong indicator of malicious activity
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
