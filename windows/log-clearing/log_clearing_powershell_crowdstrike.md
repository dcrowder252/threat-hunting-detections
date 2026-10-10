# PowerShell Used to Clear Windows Event Logs — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/08
**MITRE ATT&CK:** T1070.001, T1059.001
**Reference:** https://attack.mitre.org/techniques/T1070/001/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /(powershell\.exe|pwsh\.exe)$/i
| CommandLine = /(Clear-EventLog|ClearEventLog|System\.Diagnostics\.EventLog)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- Covers both `powershell.exe` and `pwsh.exe` to catch Windows PowerShell and PowerShell 7
- The regex covers all three common PowerShell log clearing patterns in a single expression
- `ParentBaseFileName` surfaces the parent process for additional triage context
- PowerShell Script Block Logging (Event ID 4104) can provide additional visibility into obfuscated log clearing attempts
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
- By default CrowdStrike LogScale caps results at 200 — to increase this limit add a `limit` parameter inside the table command with a value up to 20,000. Example: `| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName], sortby=@timestamp, order=desc, limit=10000)`