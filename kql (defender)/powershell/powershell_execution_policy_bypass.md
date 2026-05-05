# PowerShell Execution Policy Bypass — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/04
**MITRE ATT&CK:** T1059.001, T1562
**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Query

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "-ExecutionPolicy Bypass",
    "-ExecutionPolicy Unrestricted",
    "-ExecutionPolicy Hidden",
    "-ep bypass",
    "-ep unrestricted",
    "-ep hidden"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Covers both `powershell.exe` and `pwsh.exe` to catch Windows PowerShell and PowerShell 7
- `-ExecutionPolicy Hidden` suppresses the PowerShell window entirely and should be treated as high priority when observed
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Software installers occasionally use bypass flags legitimately — baseline approved usage before alerting
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
