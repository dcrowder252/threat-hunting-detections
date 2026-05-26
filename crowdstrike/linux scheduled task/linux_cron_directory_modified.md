# Linux System Cron Directory or File Modified — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/26
**MITRE ATT&CK:** T1053.003
**Reference:** https://attack.mitre.org/techniques/T1053/003/

---

## Query

```kusto
#event_simpleName=FileWritten
| event_platform=Lin
| TargetFileName = /(\/etc\/cron\.(d|daily|hourly|weekly|monthly)\/|\/etc\/crontab|\/var\/spool\/cron\/crontabs\/)/i
| table(_time, ComputerName, UserName, TargetFileName, ImageFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `event_platform=Lin` filters results to Linux endpoints only
- `FileWritten` is the CrowdStrike event for file creation and modification activity
- The regex covers all common system cron directory and file locations in a single expression
- Package manager activity may generate false positives when installing or updating software that includes cron jobs — baseline approved activity before alerting
- `ImageFileName` surfaces the process that wrote the file for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known software deployment and maintenance baselines before alerting
