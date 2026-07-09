# Linux System Cron Directory or File Modified — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/26
**MITRE ATT&CK:** T1053.003
**Reference:** https://attack.mitre.org/techniques/T1053/003/

---

## Query

```kusto
#event_simpleName=NewScriptWritten
| event_platform=Lin
| TargetFileName = /(\/etc\/cron\.(d|daily|hourly|weekly|monthly)\/|\/etc\/crontab|\/var\/spool\/cron\/crontabs\/)/i
| table(@timestamp, ComputerName, UserName, TargetFileName, ImageFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `event_platform=Lin` filters results to Linux endpoints only
- `NewScriptWritten` is used as the event name and was validated in testing — some tenants may surface this activity under `FileWritten` instead, so adjust the event name as necessary for your environment
- The regex covers all common system cron directory and file locations in a single expression
- Package manager activity may generate false positives when installing or updating software that includes cron jobs — baseline approved activity before alerting
- `ImageFileName` surfaces the process that wrote the file for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known software deployment and maintenance baselines before alerting
