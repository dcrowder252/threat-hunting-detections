# Linux Shred Command Used Against Log Files — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/25
**MITRE ATT&CK:** T1070.002, T1070.003
**Reference:** https://attack.mitre.org/techniques/T1070/002/

---

## Query

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
CommandLine="*shred*"
(
    CommandLine="*/var/log/*" OR
    CommandLine="*.bash_history*"
)
| table _time, host, user, CommandLine, ParentCommandLine
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- Common Linux log sourcetypes include `linux_audit`, `syslog`, `linux_secure`, and `auditd` — adjust based on your Splunk configuration
- Auditd is recommended as the primary data source for Linux process execution telemetry as it provides richer command-line visibility than syslog alone
- The query is scoped to shred activity targeting log files and bash history files specifically to reduce noise from legitimate use of shred against other files
- Shred used against log files or history files has very few legitimate explanations and should be treated as high priority when detected
- Field names for Linux logs may differ significantly from Windows logs — adjust based on your specific log source and parsing configuration
- Review results against known administrative baselines before alerting
