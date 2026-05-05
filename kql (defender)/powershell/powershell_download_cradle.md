# PowerShell Download Cradle Execution — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/04
**MITRE ATT&CK:** T1059.001, T1105, T1027
**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Query

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "IEX",
    "Invoke-Expression",
    "DownloadString",
    "DownloadFile",
    "Net.WebClient",
    "Invoke-WebRequest",
    "WebRequest",
    "curl",
    "wget"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Covers both `powershell.exe` and `pwsh.exe` to catch Windows PowerShell and PowerShell 7
- `curl` and `wget` are included as PowerShell 7 supports both natively
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- These patterns should be investigated in context — presence alongside encoded commands or unusual parent processes significantly increases likelihood of malicious activity
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
