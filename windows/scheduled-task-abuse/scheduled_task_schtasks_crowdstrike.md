# Schtasks.exe Used to Create or Modify Scheduled Task — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/24
**MITRE ATT&CK:** T1053.005, T1059.001
**Reference:** https://attack.mitre.org/techniques/T1053/005/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /schtasks\.exe$/i
| CommandLine = /(\s\/create\s|\s\/change\s)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- The regex matches both `/create` and `/change` arguments with surrounding whitespace to avoid partial string matches
- The `/change` flag can generate significant noise in most environments — consider removing it and hunting `/create` only to reduce unwanted results
- Removing false positives based on `ParentBaseFileName` may be necessary to further cut down on noise — common noisy parent processes include software update managers, endpoint agents, and Office components
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
- By default CrowdStrike LogScale caps results at 200 — to increase this limit add a `limit` parameter inside the table command with a value up to 20,000. Example: `| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName], sortby=@timestamp, order=desc, limit=10000)`