# Windows Event Log Cleared — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/08
**MITRE ATT&CK:** T1070.001
**Reference:** https://attack.mitre.org/techniques/T1070/001/

---

## Query — Tenants Without Windows Event Log Ingestion

For environments where Windows Event Logs are not ingested into LogScale or NextGen SIEM, this query relies on native CrowdStrike telemetry to detect Event Log clearing activity.

```kusto
#event_simpleName=EventLogCleared
| table(@timestamp, ComputerName, UserName, TargetFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query — Tenants With Windows Event Log Ingestion

For environments where Windows Event Logs are ingested into LogScale or NextGen SIEM, this query leverages EventID 104 and the additional field visibility that comes with ingested event log data.

```kusto
#event_simpleName=EventLogCleared
| EventID = 104
| table(@timestamp, ComputerName, UserName, SubjectUserName, SubjectDomainName, SubjectLogonId, Channel)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `EventLogCleared` is the native CrowdStrike event generated when a Windows Event Log is cleared
- EventID 104 is only available in tenants that ingest Windows Event Logs into LogScale or NextGen SIEM
- `Channel` identifies which specific log was cleared and is an important triage field — only available in tenants with Windows Event Log ingestion
- `SubjectUserName`, `SubjectDomainName`, and `SubjectLogonId` are Windows Event Log fields and may not be available in all tenants
- Any occurrence outside of an approved maintenance window should be investigated immediately
- Field names may vary across tenants — adjust as necessary for your environment
