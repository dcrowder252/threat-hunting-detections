# Windows Event Log Cleared — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/06
**MITRE ATT&CK:** T1070.001
**Reference:** https://attack.mitre.org/techniques/T1070/001/

---

## Query

```spl
index=windows sourcetype="WinEventLog:System"
EventCode=104
| table _time, ComputerName, SubjectUserName, SubjectDomainName, SubjectLogonId, Channel
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 104 is generated whenever any Windows Event Log is cleared via the Event Log service
- `Channel` identifies which specific log was cleared and is an important triage field
- `SubjectUserName` and `SubjectDomainName` identify the account responsible for clearing the log
- `SubjectLogonId` can be used to correlate with other events from the same logon session
- Any occurrence outside of an approved maintenance window should be investigated immediately
- Field names may vary depending on your Splunk configuration and data inputs
