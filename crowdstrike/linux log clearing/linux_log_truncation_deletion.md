# Linux Log File Truncation or Deletion — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/25
**MITRE ATT&CK:** T1070.002
**Reference:** https://attack.mitre.org/techniques/T1070/002/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine = /(truncate\s+-s\s+0|>\s*\/var\/log\/|(rm\s+.*\/var\/log\/))/i
| table(_time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `event_platform=Lin` filters results to Linux endpoints only
- `ProcessRollup2` is the standard CrowdStrike event for process creation across all platforms
- The regex covers truncation and deletion patterns targeting `/var/log/` in a single expression
- The `rm` pattern is scoped to `/var/log/` to avoid matching unrelated file deletions
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Log rotation scripts may generate false positives — establish a baseline of approved log management activity before alerting
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
