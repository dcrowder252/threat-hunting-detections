# Windows Event Log Cleared — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/08
**MITRE ATT&CK:** T1070.001
**Reference:** https://attack.mitre.org/techniques/T1070/001/

---

## Query

```kusto
#event_simpleName=EventLogCleared
| EventID = 104
| table(_time, ComputerName, UserName, SubjectUserName, SubjectDomainName, SubjectLogonId, Channel)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- EventID 104 is generated whenever any Windows Event Log is cleared via the Event Log service
- `Channel` identifies which specific log was cleared and is an important triage field
- `SubjectUserName` and `SubjectDomainName` identify the account responsible for clearing the log
- `SubjectLogonId` can be used to correlate with other events from the same logon session
- Any occurrence outside of an approved maintenance window should be investigated immediately
- Field names may vary across tenants — adjust as necessary for your environment
