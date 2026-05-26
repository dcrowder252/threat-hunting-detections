# Linux Crontab Modification — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/26
**MITRE ATT&CK:** T1053.003, T1059.004
**Reference:** https://attack.mitre.org/techniques/T1053/003/

---

## Query

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
Image="*/crontab"
(
    CommandLine="*crontab -e*" OR
    CommandLine="*crontab -r*" OR
    CommandLine="*crontab -l*"
)
| table _time, host, user, CommandLine, ParentCommandLine
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- Common Linux log sourcetypes include `linux_audit`, `syslog`, `linux_secure`, and `auditd` — adjust based on your Splunk configuration
- Auditd is recommended as the primary data source for Linux process execution telemetry as it provides richer command-line visibility than syslog alone
- Pay particular attention to crontab modifications on servers and cloud workloads where interactive user activity is not expected
- Field names for Linux logs may differ significantly from Windows logs — adjust based on your specific log source and parsing configuration
- Review results against known administrative baselines before alerting
