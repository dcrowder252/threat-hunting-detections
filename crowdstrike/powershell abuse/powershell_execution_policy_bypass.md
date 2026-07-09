# PowerShell Execution Policy Bypass — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/04
**MITRE ATT&CK:** T1059.001, T1562
**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /(powershell\.exe|pwsh\.exe)$/i
| CommandLine = /(-ExecutionPolicy\s+(Bypass|Unrestricted|Hidden)|-ep\s+(bypass|unrestricted|hidden))/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- The regex covers both full and abbreviated bypass flag variations in a single clean expression
- `-ExecutionPolicy Hidden` suppresses the PowerShell window entirely and should be treated as high priority when observed
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Software installers occasionally use bypass flags legitimately — baseline approved usage before alerting
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
