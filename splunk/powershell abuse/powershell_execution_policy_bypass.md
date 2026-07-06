# PowerShell Execution Policy Bypass — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/04
**MITRE ATT&CK:** T1059.001, T1562
**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Query

```spl
index=windows sourcetype="WinEventLog:Security" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=4688 OR EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(
    CommandLine="*-ExecutionPolicy Bypass*" OR
    CommandLine="*-ExecutionPolicy Unrestricted*" OR
    CommandLine="*-ExecutionPolicy Hidden*" OR
    CommandLine="*-ep bypass*" OR
    CommandLine="*-ep unrestricted*" OR
    CommandLine="*-ep hidden*"
)
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- `-ExecutionPolicy Hidden` suppresses the PowerShell window entirely and should be treated as high priority when observed
- Software installers occasionally use bypass flags legitimately — baseline approved usage before alerting
- Field names may vary depending on your Splunk configuration and data inputs
- Review results against known administrative baselines before alerting
