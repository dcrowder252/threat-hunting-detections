# Linux Logging Service Stopped or Disabled — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/25
**MITRE ATT&CK:** T1070.002, T1562.001
**Reference:** https://attack.mitre.org/techniques/T1070/002/

---

## Query

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(
    (CommandLine="*systemctl*" AND (
        CommandLine="*stop rsyslog*" OR
        CommandLine="*stop syslog*" OR
        CommandLine="*stop auditd*" OR
        CommandLine="*disable rsyslog*" OR
        CommandLine="*disable syslog*" OR
        CommandLine="*disable auditd*"
    )) OR
    (CommandLine="*service*" AND (
        CommandLine="*rsyslog stop*" OR
        CommandLine="*syslog stop*" OR
        CommandLine="*auditd stop*"
    ))
)
| table _time, host, user, CommandLine, ParentCommandLine
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- Common Linux log sourcetypes include `linux_audit`, `syslog`, `linux_secure`, and `auditd` — adjust based on your Splunk configuration
- Auditd is recommended as the primary data source for Linux process execution telemetry as it provides richer command-line visibility than syslog alone
- Note that if auditd is the primary log source and it is stopped, visibility into subsequent activity will be lost — centralized log forwarding is essential to retaining forensic data in this scenario
- Any instance of logging services being stopped outside of an approved maintenance window should be treated as high priority
- Field names for Linux logs may differ significantly from Windows logs — adjust based on your specific log source and parsing configuration
- Review results against known administrative baselines before alerting
