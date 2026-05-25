# Linux Logging Service Stopped or Disabled — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/25
**MITRE ATT&CK:** T1070.002, T1562.001
**Reference:** https://attack.mitre.org/techniques/T1070/002/

---

## Query

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where (FileName == "systemctl" and ProcessCommandLine has_any (
    "stop rsyslog",
    "stop syslog",
    "stop auditd",
    "disable rsyslog",
    "disable syslog",
    "disable auditd"
))
or (FileName == "service" and ProcessCommandLine has_any (
    "rsyslog stop",
    "syslog stop",
    "auditd stop"
))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- The `DeviceInfo` subquery filters results to Linux endpoints only
- Both `systemctl` and `service` command patterns are covered for stopping or disabling logging services
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Note that if auditd is the primary log source and it is stopped, visibility into subsequent activity will be lost — centralized log forwarding is essential to retaining forensic data in this scenario
- Any instance of logging services being stopped outside of an approved maintenance window should be treated as high priority
- MDE Linux coverage requires Microsoft Defender for Endpoint to be deployed on Linux endpoints
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
