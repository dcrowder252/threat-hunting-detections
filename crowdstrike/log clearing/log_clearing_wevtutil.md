# Wevtutil Used to Clear Windows Event Logs — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/08
**MITRE ATT&CK:** T1070.001
**Reference:** https://attack.mitre.org/techniques/T1070/001/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /wevtutil\.exe$/i
| CommandLine = /(\scl\s|\sclear-log\s)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- The regex matches both `cl` and `clear-log` arguments with surrounding whitespace to avoid partial string matches
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Review the parent process to understand what invoked wevtutil — scripted or automated invocation is a strong indicator of malicious activity
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
