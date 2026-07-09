# Scheduled Task Modified — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/24
**MITRE ATT&CK:** T1053.005, T1036
**Reference:** https://attack.mitre.org/techniques/T1053/005/

---

## Query — Tenants Without Windows Event Log Ingestion

For environments where Windows Event Logs are not ingested into LogScale or NextGen SIEM, this query relies on native CrowdStrike telemetry to detect scheduled task modification activity.

```kusto
#event_simpleName=ScheduledTaskModified
| table(@timestamp, ComputerName, UserName, TaskName, TaskExecCommand, TaskExecArguments)
| sort(field=@timestamp, order=desc)
```

---

## Query — Tenants With Windows Event Log Ingestion

For environments where Windows Event Logs are ingested into LogScale or NextGen SIEM, this query leverages EventID 4702 and the additional field visibility that comes with ingested event log data.

```kusto
#event_simpleName=ScheduledTaskModified
| EventID = 4702
| table(@timestamp, ComputerName, UserName, SubjectUserName, SubjectDomainName, TaskName, TaskExecCommand, TaskExecArguments)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- EventID 4702 requires the Audit Other Object Access Events policy to be enabled — this is not configured by default on all Windows systems
- `TaskExecCommand` and `TaskExecArguments` surface the execution details of the updated task and should be reviewed for unexpected changes to task actions or execution context
- `SubjectUserName` and `SubjectDomainName` are Windows Event Log fields and may not be available in all tenants
- Modifications made outside of known software deployment or maintenance windows should be treated as suspicious
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known scheduled task baselines before alerting
