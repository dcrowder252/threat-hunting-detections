# PowerShell Download Cradle Execution — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/05/04
**MITRE ATT&CK:** T1059.001, T1105, T1027
**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Query

```spl
index=windows sourcetype="WinEventLog:Security" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=4688 OR EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(
    CommandLine="*IEX*" OR
    CommandLine="*Invoke-Expression*" OR
    CommandLine="*DownloadString*" OR
    CommandLine="*DownloadFile*" OR
    CommandLine="*Net.WebClient*" OR
    CommandLine="*Invoke-WebRequest*" OR
    CommandLine="*WebRequest*" OR
    CommandLine="*curl*" OR
    CommandLine="*wget*"
)
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- `curl` and `wget` are included as PowerShell 7 supports both natively
- These patterns should be investigated in context — presence alongside encoded commands or unusual parent processes significantly increases likelihood of malicious activity
- Field names may vary depending on your Splunk configuration and data inputs
- Review results against known administrative baselines before alerting
