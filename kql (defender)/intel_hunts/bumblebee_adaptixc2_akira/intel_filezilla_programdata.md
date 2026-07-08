# FileZilla Installer Executed from ProgramData — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1048.001, T1219
**Reference:** https://attack.mitre.org/techniques/T1048/001/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```kql
DeviceProcessEvents
| where FolderPath contains @"ProgramData"
| where FileName contains "FileZilla"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## IOC Query — Known Exfiltration Server

```kql
DeviceNetworkEvents
| where RemoteIP == "185.174.100.203"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- `FolderPath` and `FileName` both must match — the two consecutive where clauses act as an AND condition
- `FolderPath` identifies where the installer was executed from and is the key triage field for this detection
- The IOC query targets the exfiltration server observed in this campaign — treat as time sensitive given IOC decay
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- IOC fidelity decays over time — validate against current threat intelligence before using for alerting
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
