# Linux Systemd Timer or Service Unit Created — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/26
**MITRE ATT&CK:** T1053.006
**Reference:** https://attack.mitre.org/techniques/T1053/006/

---

## Query

```kusto
#event_simpleName=NewScriptWritten
| event_platform=Lin
| TargetFileName = /(\/etc\/systemd\/system\/|\/usr\/lib\/systemd\/system\/|\/run\/systemd\/system\/)/i
| TargetFileName = /\.(timer|service)$/i
| table(@timestamp, ComputerName, UserName, TargetFileName, ImageFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `event_platform=Lin` filters results to Linux endpoints only
- `NewScriptWritten` is used as the event name and was validated in testing — some tenants may surface this activity under `FileWritten` instead, so adjust the event name as necessary for your environment
- The first regex filters to systemd unit directories and the second filters to `.timer` and `.service` file extensions
- `ImageFileName` surfaces the process that wrote the file for additional triage context
- Package manager activity may generate false positives when installing or updating software that includes systemd unit files — baseline approved activity before alerting
- Review newly created unit files for suspicious content including references to unusual binaries, encoded commands, or network connections
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known software deployment and maintenance baselines before alerting
