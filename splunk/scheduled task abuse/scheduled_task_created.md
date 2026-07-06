# Scheduled Task Created — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/24
**MITRE ATT&CK:** T1053.005
**Reference:** https://attack.mitre.org/techniques/T1053/005/

---

## Query

```spl
index=windows sourcetype="WinEventLog:Security"
EventCode=4698
| table _time, ComputerName, SubjectUserName, SubjectDomainName, TaskName, TaskContent
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4698 requires the Audit Other Object Access Events policy to be enabled — this is not configured by default on all Windows systems
- `TaskContent` contains the full XML definition of the task and is the most valuable field for understanding what the task is configured to do
- `SubjectUserName` and `SubjectDomainName` identify the account that created the task
- Pay particular attention to tasks configured to run as SYSTEM or referencing unusual execution paths or encoded commands
- Field names may vary depending on your Splunk configuration and data inputs
- Review results against known scheduled task baselines before alerting
