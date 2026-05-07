# Windows Security Event Log Cleared — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/06
**MITRE ATT&CK:** T1070.001
**Reference:** https://attack.mitre.org/techniques/T1070/001/

---

## Query

```spl
index=windows sourcetype="WinEventLog:Security"
EventCode=1102
| table _time, ComputerName, SubjectUserName, SubjectDomainName, SubjectLogonId
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 1102 is generated whenever the Windows Security audit log is cleared
- `SubjectUserName` and `SubjectDomainName` identify the account responsible for clearing the log
- `SubjectLogonId` can be used to correlate with other events from the same logon session
- Any occurrence outside of an approved maintenance window should be investigated immediately
- Field names may vary depending on your Splunk configuration and data inputs
