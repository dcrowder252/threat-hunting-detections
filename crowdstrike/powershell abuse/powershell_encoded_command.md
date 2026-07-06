# PowerShell Encoded Command Execution — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/04/21
**MITRE ATT&CK:** T1059.001, T1027
**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /(powershell\.exe|pwsh\.exe)$/i
| CommandLine = /(-EncodedCommand|-EncodedC|-EncodC|-enc|-ec)\s/i
| table(_time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- The regex covers all common abbreviations of the encoded command flag in a single pattern
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
