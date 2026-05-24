# Scheduled Task Created — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/24
**MITRE ATT&CK:** T1053.005
**Reference:** https://attack.mitre.org/techniques/T1053/005/

---

## Query

```kusto
#event_simpleName=ScheduledTaskRegistered
| EventID = 4698
| table(_time, ComputerName, UserName, SubjectUserName, SubjectDomainName, TaskName, TaskContent)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- EventID 4698 requires the Audit Other Object Access Events policy to be enabled — this is not configured by default on all Windows systems
- `TaskContent` contains the full XML definition of the task and is the most valuable field for understanding what the task is configured to do
- `SubjectUserName` and `SubjectDomainName` identify the account that created the task
- Pay particular attention to tasks configured to run as SYSTEM or referencing unusual execution paths or encoded commands
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known scheduled task baselines before alerting
