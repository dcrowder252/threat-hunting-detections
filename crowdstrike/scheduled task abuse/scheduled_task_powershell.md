# PowerShell Used to Register Scheduled Task — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/24
**MITRE ATT&CK:** T1053.005, T1059.001
**Reference:** https://attack.mitre.org/techniques/T1053/005/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /(powershell\.exe|pwsh\.exe)$/i
| CommandLine = /(Register-ScheduledTask|New-ScheduledTaskAction|New-ScheduledTask|Set-ScheduledTask)/i
| table(_time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- Covers both `powershell.exe` and `pwsh.exe` to catch Windows PowerShell and PowerShell 7
- The regex covers all four common PowerShell scheduled task registration cmdlets in a single expression
- `ParentBaseFileName` surfaces the parent process for additional triage context
- PowerShell Script Block Logging (Event ID 4104) can provide additional visibility into obfuscated task registration attempts
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
