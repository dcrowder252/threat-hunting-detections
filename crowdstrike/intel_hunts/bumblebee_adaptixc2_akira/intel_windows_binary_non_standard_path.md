# Windows Binary Executing From Non-Standard Path — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1574.001
**Reference:** https://attack.mitre.org/techniques/T1574/001/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query — consent.exe Executing from Non-Standard Path

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /consent\.exe$/i
| ImageFileName != /\\Windows\\System32\\consent\.exe$/i
| ImageFileName != /\\Windows\\WinSxS\\.*\\consent\.exe$/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query — wab.exe Executing from Non-Standard Path

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /wab\.exe$/i
| ImageFileName != /\\Program Files\\Windows Mail\\wab\.exe$/i
| ImageFileName != /\\Windows\\WinSxS\\.*\\wab\.exe$/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- CrowdStrike rarely includes drive letters in file paths — paths typically appear in the format `\Device\HarddiskVolume4\Windows\...` so exclusions are written using relative path endings rather than full drive letter paths
- `WinSxS` is excluded in both queries as Windows stores side-by-side component copies there and generates significant false positive noise
- `wab.exe` is a Windows Address Book binary — its legitimate execution path is `Program Files\Windows Mail` not System32, so System32 is not used as an exclusion here
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
