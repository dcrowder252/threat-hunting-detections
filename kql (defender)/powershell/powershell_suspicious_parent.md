# PowerShell Spawned by Suspicious Parent Process — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/06
**MITRE ATT&CK:** T1059.001, T1566.001, T1027
**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Query

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "explorer.exe"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Covers both `powershell.exe` and `pwsh.exe` to catch Windows PowerShell and PowerShell 7
- `explorer.exe` as a parent process may have legitimate context depending on the environment — review in conjunction with command-line arguments
- Office application parent processes spawning PowerShell should be treated as high priority and investigated immediately
- `InitiatingProcessCommandLine` is included to provide additional triage context on what the parent process was doing when it spawned PowerShell
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
