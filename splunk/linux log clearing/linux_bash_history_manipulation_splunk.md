# Linux Bash History Manipulation — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/25
**MITRE ATT&CK:** T1070.003
**Reference:** https://attack.mitre.org/techniques/T1070/003/

---

## Query

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(
    CommandLine="*history -c*" OR
    CommandLine="*HISTSIZE=0*" OR
    CommandLine="*HISTFILESIZE=0*" OR
    CommandLine="*unset HISTFILE*" OR
    CommandLine="*HISTFILE=/dev/null*" OR
    CommandLine="*.bash_history*"
)
NOT CommandLine="*locate*"
| table _time, host, user, CommandLine, ParentCommandLine
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- Common Linux log sourcetypes include `linux_audit`, `syslog`, `linux_secure`, and `auditd` — adjust based on your Splunk configuration
- Auditd is recommended as the primary data source for Linux process execution telemetry as it provides richer command-line visibility than syslog alone
- `locate` is explicitly excluded as it commonly searches for `.bash_history` files as part of normal filesystem indexing activity and generates significant false positive noise
- Additional exclusions may be needed based on your environment — baseline results before alerting
- Field names for Linux logs may differ significantly from Windows logs — adjust based on your specific log source and parsing configuration
- Review results against known administrative baselines before alerting
