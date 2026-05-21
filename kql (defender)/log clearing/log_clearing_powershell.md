# PowerShell Used to Clear Windows Event Logs — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/21
**MITRE ATT&CK:** T1070.001, T1059.001
**Reference:** https://attack.mitre.org/techniques/T1070/001/

---

## Query

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "Clear-EventLog",
    "ClearEventLog",
    "System.Diagnostics.EventLog"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Covers both `powershell.exe` and `pwsh.exe` to catch Windows PowerShell and PowerShell 7
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- PowerShell Script Block Logging (Event ID 4104) can provide additional visibility into obfuscated log clearing attempts
- Review the parent process to understand what invoked PowerShell — unusual parent processes significantly increase likelihood of malicious activity
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
