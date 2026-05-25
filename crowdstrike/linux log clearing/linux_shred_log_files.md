# Linux Shred Command Used Against Log Files — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/25
**MITRE ATT&CK:** T1070.002, T1070.003
**Reference:** https://attack.mitre.org/techniques/T1070/002/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| event_platform=Lin
| ImageFileName = /\/shred$/i
| CommandLine = /(\/var\/log\/|\.bash_history)/i
| table(_time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `event_platform=Lin` filters results to Linux endpoints only
- `ProcessRollup2` is the standard CrowdStrike event for process creation across all platforms
- The query is scoped to shred activity targeting log files and bash history files specifically to reduce noise from legitimate use of shred against other files
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Shred used against log files or history files has very few legitimate explanations and should be treated as high priority when detected
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
