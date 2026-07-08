# Windows Binary Executing From Non-Standard Path — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1574.001
**Reference:** https://attack.mitre.org/techniques/T1574/001/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```kql
DeviceProcessEvents
| where FileName in~ ("consent.exe", "WAB.exe")
| where not(FolderPath startswith @"C:\Windows\System32" or FolderPath startswith @"C:\Windows\SysWOW64")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- The exclusion filter removes legitimate execution from System32 and SysWOW64 — any remaining hits represent execution from unexpected paths
- `FolderPath` identifies where the binary was executed from and is the key triage field for this detection
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
