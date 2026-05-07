# Wevtutil Used to Clear Windows Event Logs — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/06
**MITRE ATT&CK:** T1070.001
**Reference:** https://attack.mitre.org/techniques/T1070/001/

---

## Query

```spl
index=windows sourcetype="WinEventLog:Security" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=4688 OR EventCode=1
Image="*\\wevtutil.exe"
(
    CommandLine="* cl *" OR
    CommandLine="* clear-log *"
)
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- `cl` and `clear-log` are the two wevtutil arguments used to clear event logs
- Review ParentImage to understand what process invoked wevtutil — scripted or automated invocation is a strong indicator of malicious activity
- Field names may vary depending on your Splunk configuration and data inputs
- Review results against known administrative baselines before alerting
