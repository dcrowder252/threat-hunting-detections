# PowerShell Spawned by Suspicious Parent Process — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/06
**MITRE ATT&CK:** T1059.001, T1566.001, T1027
**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Query

```spl
index=windows sourcetype="WinEventLog:Security" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=4688 OR EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(
    ParentImage="*\\winword.exe" OR
    ParentImage="*\\excel.exe" OR
    ParentImage="*\\powerpnt.exe" OR
    ParentImage="*\\outlook.exe" OR
    ParentImage="*\\mshta.exe" OR
    ParentImage="*\\wscript.exe" OR
    ParentImage="*\\cscript.exe" OR
)
| table _time, ComputerName, User, Image, CommandLine, ParentImage, ParentCommandLine
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- Office application parent processes spawning PowerShell should be treated as high priority and investigated immediately
- Field names may vary depending on your Splunk configuration and data inputs
- Review results against known administrative baselines before alerting
