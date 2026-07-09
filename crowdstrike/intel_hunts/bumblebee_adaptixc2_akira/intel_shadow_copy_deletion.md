# Shadow Copy Deletion via PowerShell — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1490, T1070
**Reference:** https://attack.mitre.org/techniques/T1490/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /(powershell\.exe|pwsh\.exe)$/i
| CommandLine = /Win32_Shadowcopy/i
| CommandLine = /Remove-WmiObject/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- Covers both `powershell.exe` and `pwsh.exe` to catch Windows PowerShell and PowerShell 7
- Both `Win32_Shadowcopy` and `Remove-WmiObject` must be present in the command line — consecutive filter lines in LogScale act as an AND condition
- This combination is a strong ransomware precursor indicator and should be treated as a critical alert
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
