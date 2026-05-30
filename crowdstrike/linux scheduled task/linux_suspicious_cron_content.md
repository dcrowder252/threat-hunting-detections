# Linux Suspicious Cron Job Content — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/26
**MITRE ATT&CK:** T1053.003, T1059.004, T1027
**Reference:** https://attack.mitre.org/techniques/T1053/003/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| event_platform=Lin
| ParentBaseFileName = /(cron|crond)$/i
| CommandLine = /(\/tmp\/|\/dev\/shm\/|base64|curl|wget|python\s+-c|perl\s+-e|bash\s+-i|nc\s+|ncat)/i
| table(_time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `event_platform=Lin` filters results to Linux endpoints only
- `ProcessRollup2` is the standard CrowdStrike event for process creation across all platforms
- `ParentBaseFileName` is filtered to `cron` or `crond` to ensure results are limited to processes spawned directly by the cron daemon
- The regex covers common suspicious patterns associated with malicious cron job content in a single expression
- This query targets the execution of cron jobs containing suspicious patterns rather than the creation of cron entries — useful for identifying persistence that may already be established
- Legitimate cron jobs that use curl or wget for approved automated downloads may generate false positives — baseline approved cron job content before alerting
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
