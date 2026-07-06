# RMM Domain Communication — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/04/21
**MITRE ATT&CK:** T1219.002
**Reference:** https://attack.mitre.org/techniques/T1219/002/

---

## Query

```kql
DeviceNetworkEvents
| where ActionType == 'DnsConnectionInspected'
| extend json = todynamic(AdditionalFields)
| extend RemoteUrl = tolower(tostring(json.query))
| where RemoteUrl has_any (
    '.anydesk.com',
    '.teamviewer.com',
    '.screenconnect.com',
    '.atera.com',
    '.splashtop.com',
    '.splashtop.eu'
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- This list is not exhaustive — add additional RMM-related domains as needed
- Review results against your approved RMM tool baseline before alerting
