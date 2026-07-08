# NTDS.dit Extraction via wbadmin.exe — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1003.003
**Reference:** https://attack.mitre.org/techniques/T1003/003/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /wbadmin\.exe$/i
| CommandLine = /(ntds\.dit|start\s+backup)/i
| table(_time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- The regex matches both explicit ntds.dit references and the start backup argument
- This activity is rarely legitimate outside of approved domain controller backup operations — any hit outside of a known maintenance window should be treated as high priority
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
