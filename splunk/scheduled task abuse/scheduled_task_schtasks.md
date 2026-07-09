# Schtasks.exe Used to Create or Modify Scheduled Task — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/24
**MITRE ATT&CK:** T1053.005, T1059.001
**Reference:** https://attack.mitre.org/techniques/T1053/005/

---

## Query

```spl
index=windows sourcetype="WinEventLog:Security" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=4688 OR EventCode=1
Image="*\\schtasks.exe"
(
    CommandLine="* /create *" OR
    CommandLine="* /change *"
)
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- Spaces surrounding `/create` and `/change` are intentional to avoid partial string matches on other schtasks arguments
- The `/change` flag can generate significant noise in most environments — consider removing it and hunting `/create` only to reduce unwanted results
- Removing false positives based on the parent process (`ParentImage`) may be necessary to further cut down on noise — common noisy parent processes include software update managers, endpoint agents, and Office components
- Field names may vary depending on your Splunk configuration and data inputs
- Review results against known administrative baselines before alerting
