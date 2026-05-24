# Schtasks.exe Used to Create or Modify Scheduled Task — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/24
**MITRE ATT&CK:** T1053.005, T1059.001
**Reference:** https://attack.mitre.org/techniques/T1053/005/

---

## Query

```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any (
    " /create ",
    " /change "
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Spaces surrounding `/create` and `/change` are intentional to avoid partial string matches on other schtasks arguments
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Review the full command-line arguments for unusual execution paths, encoded commands, or references to scripting engines
- Review the parent process to understand what invoked schtasks.exe — scripted or automated invocation is a strong indicator of malicious activity
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
