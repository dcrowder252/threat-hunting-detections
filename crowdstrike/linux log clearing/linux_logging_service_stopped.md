# Linux Logging Service Stopped or Disabled — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/25
**MITRE ATT&CK:** T1070.002, T1562.001
**Reference:** https://attack.mitre.org/techniques/T1070/002/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| event_platform=Lin
| CommandLine = /((systemctl\s+(stop|disable)\s+(rsyslog|syslog|auditd))|(service\s+(rsyslog|syslog|auditd)\s+stop))/i
| table(_time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `event_platform=Lin` filters results to Linux endpoints only
- `ProcessRollup2` is the standard CrowdStrike event for process creation across all platforms
- The regex covers both `systemctl` and `service` command patterns for stopping or disabling logging services in a single expression
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Note that if auditd is the primary log source and it is stopped, visibility into subsequent activity will be lost — centralized log forwarding is essential to retaining forensic data in this scenario
- Any instance of logging services being stopped outside of an approved maintenance window should be treated as high priority
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
