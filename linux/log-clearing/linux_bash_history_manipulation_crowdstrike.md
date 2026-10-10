# Linux Bash History Manipulation — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/25
**MITRE ATT&CK:** T1070.003
**Reference:** https://attack.mitre.org/techniques/T1070/003/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine = /(history\s+-c|HISTSIZE=0|HISTFILESIZE=0|unset\s+HISTFILE|HISTFILE=\/dev\/null|rm\s+.*\.bash_history|truncate\s+-s\s+0\s+.*\.bash_history|shred\s+.*\.bash_history)/i
| ImageFileName != /\/locate$/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `event_platform=Lin` filters results to Linux endpoints only
- `ProcessRollup2` is the standard CrowdStrike event for process creation across all platforms
- The regex consolidates multiple bash history tampering techniques into a single expression — clearing, unsetting, redirecting, deleting, truncating, and shredding `.bash_history`
- `locate` is explicitly excluded as it commonly searches for `.bash_history` files as part of normal filesystem indexing activity and generates significant false positive noise
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
- By default CrowdStrike LogScale caps results at 200 — to increase this limit add a `limit` parameter inside the table command with a value up to 20,000. Example: `| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName], sortby=@timestamp, order=desc, limit=10000)`