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
| table(_time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- The regex matches both `/create` and `/change` arguments with surrounding whitespace to avoid partial string matches on other schtasks arguments
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Review the full command-line arguments for unusual execution paths, encoded commands, or references to scripting engines
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
