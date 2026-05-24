# PowerShell Used to Register Scheduled Task — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/24
**MITRE ATT&CK:** T1053.005, T1059.001
**Reference:** https://attack.mitre.org/techniques/T1053/005/

---

## Query

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "Register-ScheduledTask",
    "New-ScheduledTaskAction",
    "New-ScheduledTask",
    "Set-ScheduledTask"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Covers both `powershell.exe` and `pwsh.exe` to catch Windows PowerShell and PowerShell 7
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- PowerShell Script Block Logging (Event ID 4104) can provide additional visibility into obfuscated task registration attempts
- Review the parent process to understand what invoked PowerShell — unusual parent processes significantly increase likelihood of malicious activity
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
