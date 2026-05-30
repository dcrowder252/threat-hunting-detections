# Linux Suspicious Cron Job Content — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/30
**MITRE ATT&CK:** T1053.003, T1059.004, T1027
**Reference:** https://attack.mitre.org/techniques/T1053/003/

---

## Query

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where InitiatingProcessFileName in ("cron", "crond")
| where ProcessCommandLine has_any (
    "/tmp/",
    "/dev/shm/",
    "base64",
    "curl",
    "wget",
    "python -c",
    "perl -e",
    "bash -i",
    "nc ",
    "ncat"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- The `DeviceInfo` subquery filters results to Linux endpoints only
- `InitiatingProcessFileName` is filtered to `cron` or `crond` to ensure results are limited to processes spawned directly by the cron daemon
- This query targets the execution of cron jobs containing suspicious patterns rather than the creation of cron entries — useful for identifying persistence that may already be established
- Legitimate cron jobs that use curl or wget for approved automated downloads may generate false positives — baseline approved cron job content before alerting
- MDE Linux coverage requires Microsoft Defender for Endpoint to be deployed on Linux endpoints
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
