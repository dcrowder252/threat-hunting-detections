# PowerShell Spawned by Suspicious Parent Process — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/06
**MITRE ATT&CK:** T1059.001, T1566.001, T1027
**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /(powershell\.exe|pwsh\.exe)$/i
| ParentBaseFileName = /(winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|mshta\.exe|wscript\.exe|cscript\.exe|explorer\.exe)$/i
| table(_time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- The regex covers all suspicious parent processes from the hunt document in a single clean expression
- `explorer.exe` as a parent process may have legitimate context depending on the environment — review in conjunction with command-line arguments
- Office application parent processes spawning PowerShell should be treated as high priority and investigated immediately
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
