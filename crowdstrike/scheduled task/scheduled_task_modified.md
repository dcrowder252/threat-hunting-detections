# Scheduled Task Modified — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/24
**MITRE ATT&CK:** T1053.005, T1036
**Reference:** https://attack.mitre.org/techniques/T1053/005/

---

## Query

```kusto
#event_simpleName=ScheduledTaskRegistered
| EventID = 4702
| table(_time, ComputerName, UserName, SubjectUserName, SubjectDomainName, TaskName, TaskContent)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- EventID 4702 requires the Audit Other Object Access Events policy to be enabled — this is not configured by default on all Windows systems
- `TaskContent` contains the full XML definition of the updated task and should be reviewed for unexpected changes to task actions, triggers, or execution context
- `SubjectUserName` and `SubjectDomainName` identify the account that modified the task
- Modifications made outside of known software deployment or maintenance windows should be treated as suspicious
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known scheduled task baselines before alerting
