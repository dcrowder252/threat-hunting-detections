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
| CommandLine = /(truncate\s+-s\s+0|>{1,2}\s*\/var\/log\/|(rm\s+.*\/var\/log\/))/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `event_platform=Lin` filters results to Linux endpoints only
- `ProcessRollup2` is the standard CrowdStrike event for process creation across all platforms
- `>{1,2}` matches both `>` and `>>` redirection operators — `>` overwrites file contents while `>>` appends and can be used to flood log files with junk data to obscure legitimate entries
- The `rm` pattern is scoped to `/var/log/` to avoid matching unrelated file deletions
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Log rotation scripts may generate false positives — establish a baseline of approved log management activity before alerting
- Field names may vary across tenants — adjust as necessary for your environment
- This detection can be very noisy — if `>>` generates too much noise consider focusing on `>` only, or narrowing results by filtering on specific usernames known to perform legitimate log management
- Review results against known administrative baselines before alerting
