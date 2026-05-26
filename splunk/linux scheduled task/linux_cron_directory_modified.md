# Linux System Cron Directory or File Modified — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/26
**MITRE ATT&CK:** T1053.003
**Reference:** https://attack.mitre.org/techniques/T1053/003/

---

## Query

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(
    TargetFilename="*/etc/cron.d/*" OR
    TargetFilename="*/etc/cron.daily/*" OR
    TargetFilename="*/etc/cron.hourly/*" OR
    TargetFilename="*/etc/cron.weekly/*" OR
    TargetFilename="*/etc/cron.monthly/*" OR
    TargetFilename="*/etc/crontab*" OR
    TargetFilename="*/var/spool/cron/crontabs/*"
)
| table _time, host, user, TargetFilename, Image
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- Common Linux log sourcetypes include `linux_audit`, `syslog`, `linux_secure`, and `auditd` — adjust based on your Splunk configuration
- This query relies on file event telemetry — auditd file watch rules must be configured to monitor cron directories for this query to return results
- Package manager activity may generate false positives when installing or updating software that includes cron jobs — baseline approved activity before alerting
- Field names for Linux logs may differ significantly from Windows logs — adjust based on your specific log source and parsing configuration
- Review results against known software deployment and maintenance baselines before alerting
