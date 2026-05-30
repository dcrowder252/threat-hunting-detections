# Linux System Cron Directory or File Modified — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/30
**MITRE ATT&CK:** T1053.003
**Reference:** https://attack.mitre.org/techniques/T1053/003/

---

## Query

```kql
DeviceFileEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where FolderPath has_any (
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/var/spool/cron/crontabs/"
)
or (FolderPath == "/etc/" and FileName == "crontab")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- The `DeviceInfo` subquery filters results to Linux endpoints only
- `DeviceFileEvents` is used rather than `DeviceProcessEvents` as this query monitors for file system activity
- `InitiatingProcessFileName` surfaces the process that wrote the file for additional triage context
- Package manager activity may generate false positives when installing or updating software that includes cron jobs — baseline approved activity before alerting
- MDE Linux coverage requires Microsoft Defender for Endpoint to be deployed on Linux endpoints
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known software deployment and maintenance baselines before alerting
