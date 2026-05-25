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
| CommandLine = /(history\s+-c|HISTSIZE=0|HISTFILESIZE=0|unset\s+HISTFILE|HISTFILE=\/dev\/null|\.bash_history)/i
| ImageFileName != /\/locate$/i
| table(_time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `event_platform=Lin` filters results to Linux endpoints only
- `ProcessRollup2` is the standard CrowdStrike event for process creation across all platforms
- The regex covers all common bash history manipulation patterns in a single expression
- `locate` is explicitly excluded as it commonly searches for `.bash_history` files as part of normal filesystem indexing activity and generates significant false positive noise
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Additional exclusions may be needed based on your environment — baseline results before alerting
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
