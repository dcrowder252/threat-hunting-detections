# Linux Systemd Timer or Service Unit Created — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/26
**MITRE ATT&CK:** T1053.006
**Reference:** https://attack.mitre.org/techniques/T1053/006/

---

## Query

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(
    TargetFilename="*/etc/systemd/system/*" OR
    TargetFilename="*/usr/lib/systemd/system/*" OR
    TargetFilename="*/run/systemd/system/*"
)
(
    TargetFilename="*.timer" OR
    TargetFilename="*.service"
)
| table _time, host, user, TargetFilename, Image
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- Common Linux log sourcetypes include `linux_audit`, `syslog`, `linux_secure`, and `auditd` — adjust based on your Splunk configuration
- This query relies on file event telemetry — auditd file watch rules must be configured to monitor systemd directories for this query to return results
- Package manager activity may generate false positives when installing or updating software that includes systemd unit files — baseline approved activity before alerting
- Review newly created unit files for suspicious content including references to unusual binaries, encoded commands, or network connections
- Field names for Linux logs may differ significantly from Windows logs — adjust based on your specific log source and parsing configuration
- Review results against known software deployment and maintenance baselines before alerting
