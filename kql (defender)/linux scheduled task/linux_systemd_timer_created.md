# Linux Systemd Timer or Service Unit Created — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/30
**MITRE ATT&CK:** T1053.006
**Reference:** https://attack.mitre.org/techniques/T1053/006/

---

## Query

```kql
DeviceFileEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where FolderPath has_any (
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/run/systemd/system/"
)
| where FileName endswith ".timer" or FileName endswith ".service"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- The `DeviceInfo` subquery filters results to Linux endpoints only
- `DeviceFileEvents` is used rather than `DeviceProcessEvents` as this query monitors for file system activity
- `InitiatingProcessFileName` surfaces the process that created the unit file for additional triage context
- Package manager activity may generate false positives when installing or updating software that includes systemd unit files — baseline approved activity before alerting
- Review newly created unit files for suspicious content including references to unusual binaries, encoded commands, or network connections
- MDE Linux coverage requires Microsoft Defender for Endpoint to be deployed on Linux endpoints
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known software deployment and maintenance baselines before alerting
