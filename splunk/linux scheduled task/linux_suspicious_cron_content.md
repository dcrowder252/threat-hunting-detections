# Linux Suspicious Cron Job Content — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/26
**MITRE ATT&CK:** T1053.003, T1059.004, T1027
**Reference:** https://attack.mitre.org/techniques/T1053/003/

---

## Query

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(ParentImage="*/cron" OR ParentImage="*/crond")
(
    CommandLine="*/tmp/*" OR
    CommandLine="*/dev/shm/*" OR
    CommandLine="*base64*" OR
    CommandLine="*curl*" OR
    CommandLine="*wget*" OR
    CommandLine="*python -c*" OR
    CommandLine="*perl -e*" OR
    CommandLine="*bash -i*" OR
    CommandLine="*nc *" OR
    CommandLine="*ncat*"
)
| table _time, host, user, CommandLine, ParentCommandLine, ParentImage
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- Common Linux log sourcetypes include `linux_audit`, `syslog`, `linux_secure`, and `auditd` — adjust based on your Splunk configuration
- Auditd is recommended as the primary data source for Linux process execution telemetry as it provides richer command-line visibility than syslog alone
- This query targets the execution of cron jobs containing suspicious patterns rather than the creation of cron entries — useful for identifying persistence that may already be established
- Legitimate cron jobs that use curl or wget for approved automated downloads may generate false positives — baseline approved cron job content before alerting
- Field names for Linux logs may differ significantly from Windows logs — adjust based on your specific log source and parsing configuration
- Review results against known administrative baselines before alerting
