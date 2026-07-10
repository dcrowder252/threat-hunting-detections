# Linux Crontab Modification — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/30
**MITRE ATT&CK:** T1053.003, T1059.004
**Reference:** https://attack.mitre.org/techniques/T1053/003/

---

## Query

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where FileName == "crontab"
| where ProcessCommandLine has_any (
    "crontab -e",
    "crontab -r",
    "crontab -l"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- The `DeviceInfo` subquery filters results to Linux endpoints only
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Pay particular attention to crontab modifications on servers and cloud workloads where interactive user activity is not expected
- The `-l` flag lists existing crontab entries and can generate significant noise in most environments — consider removing it and focusing on `-e` and `-r` only to reduce unwanted results
- MDE Linux coverage requires Microsoft Defender for Endpoint to be deployed on Linux endpoints
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
