# PowerShell Encoded Command Execution — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/04/21
**MITRE ATT&CK:** T1059.001, T1027
**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Query

```spl
index=windows sourcetype="WinEventLog:Security" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=4688 OR EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(
    CommandLine="* -EncodedCommand *" OR
    CommandLine="* -EncodedC *" OR
    CommandLine="* -EncodC *" OR
    CommandLine="* -enc *" OR
    CommandLine="* -ec *"
)
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- Field names may vary depending on your Splunk configuration and data inputs
- In large environments computer accounts (ending in `$`) may generate significant volume from legitimate management tooling such as SCCM, Group Policy, and automation frameworks — baseline which specific computer accounts are expected to run encoded commands and exclude those rather than excluding all computer accounts broadly
- Computer accounts running encoded PowerShell should not be dismissed as automatically benign — when malware or a malicious scheduled task runs as SYSTEM, network authentication goes out under the computer account, making these events worth investigating
- Review results against known administrative baselines before alerting
