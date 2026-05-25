# Linux Log File Truncation or Deletion — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/25
**MITRE ATT&CK:** T1070.002
**Reference:** https://attack.mitre.org/techniques/T1070/002/

---

## Query

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(
    CommandLine="*truncate -s 0*" OR
    CommandLine="*> /var/log/*" OR
    CommandLine="*>> /var/log/*" OR
    (CommandLine="*rm *" AND CommandLine="*/var/log/*")
)
| table _time, host, user, CommandLine, ParentCommandLine
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- Common Linux log sourcetypes include `linux_audit`, `syslog`, `linux_secure`, and `auditd` — adjust based on your Splunk configuration
- Auditd is recommended as the primary data source for Linux process execution telemetry as it provides richer command-line visibility than syslog alone
- Both `>` and `>>` redirection operators are included — `>` overwrites file contents while `>>` appends and can be used to flood log files with junk data to obscure legitimate entries
- The `rm` condition is paired with `/var/log/` to avoid matching unrelated file deletions
- Log rotation scripts may generate false positives — establish a baseline of approved log management activity before alerting
- Field names for Linux logs may differ significantly from Windows logs — adjust based on your specific log source and parsing configuration
- Review results against known administrative baselines before alerting
