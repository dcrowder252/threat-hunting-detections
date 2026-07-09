# Windows Binary Executing From Non-Standard Path — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1574.001
**Reference:** https://attack.mitre.org/techniques/T1574/001/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query — consent.exe Executing from Non-Standard Path

```kql
DeviceProcessEvents
| where FileName =~ "consent.exe"
| where not(FolderPath startswith @"C:\Windows\System32" or FolderPath contains @"\Windows\WinSxS\")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query — wab.exe Executing from Non-Standard Path

```kql
DeviceProcessEvents
| where FileName =~ "wab.exe"
| where not(FolderPath startswith @"C:\Program Files\Windows Mail" or FolderPath contains @"\Windows\WinSxS\")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- WinSxS is excluded in both queries as Windows stores side-by-side component copies there and generates significant false positive noise
- wab.exe is a Windows Address Book binary — its legitimate execution path is Program Files\Windows Mail not System32, so System32 is not used as an exclusion here
- `FolderPath` identifies where the binary was executed from and is the key triage field for this detection
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
