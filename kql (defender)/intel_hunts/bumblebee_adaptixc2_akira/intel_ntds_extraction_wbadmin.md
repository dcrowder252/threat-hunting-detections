# NTDS.dit Extraction via wbadmin.exe — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1003.003
**Reference:** https://attack.mitre.org/techniques/T1003/003/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```kql
DeviceProcessEvents
| where FileName =~ "wbadmin.exe"
| where ProcessCommandLine has_any (
    "ntds.dit",
    "start backup"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- This activity is rarely legitimate outside of approved domain controller backup operations — any hit outside of a known maintenance window should be treated as high priority
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
