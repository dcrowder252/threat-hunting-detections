# PowerShell Used to Register Scheduled Task — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/24
**MITRE ATT&CK:** T1053.005, T1059.001
**Reference:** https://attack.mitre.org/techniques/T1053/005/

---

## Query

```spl
index=windows sourcetype="WinEventLog:Security" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=4688 OR EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(
    CommandLine="*Register-ScheduledTask*" OR
    CommandLine="*New-ScheduledTaskAction*" OR
    CommandLine="*New-ScheduledTask*" OR
    CommandLine="*Set-ScheduledTask*"
)
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- PowerShell Script Block Logging (Event ID 4104) can provide additional visibility into obfuscated task registration attempts
- Review the full command-line arguments for unusual execution paths, encoded commands, or references to external resources
- Review ParentImage to understand what process invoked PowerShell — unusual parent processes significantly increase likelihood of malicious activity
- Field names may vary depending on your Splunk configuration and data inputs
- Review results against known administrative baselines before alerting
