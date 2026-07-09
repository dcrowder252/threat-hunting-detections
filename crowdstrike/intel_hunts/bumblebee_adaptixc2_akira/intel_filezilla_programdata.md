# FileZilla Installer Executed from ProgramData — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1048.001, T1219
**Reference:** https://attack.mitre.org/techniques/T1048/001/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /\\ProgramData\\/i
| ImageFileName = /FileZilla/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## IOC Query — Known Exfiltration Server

```kusto
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4 = "185.174.100.203"
| table(@timestamp, ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- Both `ProgramData` and `FileZilla` must be present in the image path — consecutive filter lines act as an AND condition in LogScale
- The IOC query uses `NetworkConnectIP4` to hunt for outbound connections to the known exfiltration server observed in this campaign
- `ContextBaseFileName` identifies the process making the outbound connection — `UserName` and `ImageFileName` are not available in network connect events
- IOC fidelity decays over time — validate against current threat intelligence before using for alerting
- `ParentBaseFileName` surfaces the parent process for additional triage context in the main query
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
