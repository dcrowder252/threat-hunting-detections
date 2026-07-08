# Windows Binary Executing From Non-Standard Path — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1574.001
**Reference:** https://attack.mitre.org/techniques/T1574/001/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /(consent\.exe|WAB\.exe)$/i
| ImageFileName != /^C:\\Windows\\(System32|SysWOW64)\\/i
| table(_time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- The exclusion filter removes legitimate execution from System32 and SysWOW64 — any remaining hits represent execution from unexpected paths
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
