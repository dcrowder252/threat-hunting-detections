# PowerShell Encoded Command Execution — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/04/21
**MITRE ATT&CK:** T1059.001, T1027
**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Query

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "-EncodedCommand",
    "-EncodedC",
    "-EncodC",
    "-enc",
    "-ec"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Covers both `powershell.exe` and `pwsh.exe` to catch Windows PowerShell and PowerShell 7
- `in~` performs a case-insensitive match on the process name
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
