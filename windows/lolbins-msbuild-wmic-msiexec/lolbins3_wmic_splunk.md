# Wmic.exe Abuse — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/09/29
**MITRE ATT&CK:** T1047
**Reference:** https://attack.mitre.org/techniques/T1047/

---

## Query 1 — Wmic Process Call Create

This query detects wmic invocations using the process call create method to execute processes locally or on remote systems. This capability is rarely used in legitimate administrative scenarios outside of specific management frameworks and is a common lateral movement and execution technique.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\wmic.exe"
CommandLine="*process*" CommandLine="*call*" CommandLine="*create*"
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 2 — Wmic Spawning Suspicious Child Process

This query detects processes spawned as children of wmic — a common technique used to obscure the origin of malicious execution by interposing wmic between the initial trigger and the ultimate payload.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
ParentImage="*\wmic.exe"
(Image="*\powershell.exe" OR
Image="*\cmd.exe" OR
Image="*\wscript.exe" OR
Image="*\cscript.exe" OR
Image="*\mshta.exe" OR
Image="*\rundll32.exe" OR
Image="*\regsvr32.exe" OR
Image="*\msiexec.exe" OR
Image="*\certutil.exe" OR
Image="*\bitsadmin.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 3 — Wmic Querying Security Software

This query detects wmic invocations querying installed security software or antivirus products — a common reconnaissance technique used by attackers to understand what security controls are present before attempting to disable or evade them.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\wmic.exe"
(CommandLine="*AntiVirusProduct*" OR
CommandLine="*FirewallProduct*" OR
CommandLine="*AntiSpywareProduct*" OR
CommandLine="*AntiMalwareProduct*" OR
CommandLine="*SecurityCenter*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- As of the September 2026 Security Update wmic.exe has been removed from Windows 11 versions 24H2 and 25H2 — detection coverage remains important for environments running older Windows versions where wmic.exe is still present
- Query 1 uses consecutive CommandLine conditions which act as an AND — all three terms must be present
- Query 2 monitors for wmic as a parent process rather than the primary process — pay attention to which field is being filtered
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
