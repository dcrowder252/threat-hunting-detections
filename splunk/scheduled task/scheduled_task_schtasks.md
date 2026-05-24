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
- Review the full command-line arguments for unusual execution paths, encoded commands, or references to scripting engines
- Review ParentImage to understand what process invoked schtasks.exe — scripted or automated invocation is a strong indicator of malicious activity
- Field names may vary depending on your Splunk configuration and data inputs
- Review results against known administrative baselines before alerting
