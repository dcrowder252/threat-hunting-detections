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
- The `/change` flag can generate significant noise in most environments — consider removing it and hunting `/create` only to reduce unwanted results
- Removing false positives based on the parent process (`InitiatingProcessFileName`) may be necessary to further cut down on noise — common noisy parent processes include software update managers, endpoint agents, and Office components
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Review the full command-line arguments for unusual execution paths, encoded commands, or references to scripting engines
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
