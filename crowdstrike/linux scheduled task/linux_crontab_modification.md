# Linux Crontab Modification — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/26
**MITRE ATT&CK:** T1053.003, T1059.004
**Reference:** https://attack.mitre.org/techniques/T1053/003/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| event_platform=Lin
| ImageFileName = /\/crontab$/i
| CommandLine = /(crontab\s+(-e|-r|-l))/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `event_platform=Lin` filters results to Linux endpoints only
- `ProcessRollup2` is the standard CrowdStrike event for process creation across all platforms
- The regex covers crontab modification, removal, and list arguments in a single expression
- The `-l` flag lists existing crontab entries and can generate significant noise in most environments — consider removing it and focusing on `-e` and `-r` only to reduce unwanted results
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
