# Mshta.exe Abuse — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/08/30
**MITRE ATT&CK:** T1218.005
**Reference:** https://attack.mitre.org/techniques/T1218/005/

---

## Query 1 — Mshta Executing Remote Content

This query detects mshta invocations referencing remote URLs in the command-line arguments indicating execution of remotely hosted HTML Application content. Legitimate mshta usage typically involves locally installed HTA files and rarely references external URLs.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\mshta.exe"
(CommandLine="*http://*" OR CommandLine="*https://*" OR CommandLine="*\\\\*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 2 — Mshta Spawned by Suspicious Parent Process

This query detects mshta spawned by parent processes commonly associated with phishing-based initial access. Mshta being launched by Office applications or scripting engines is a strong indicator of a malicious document or file execution.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\mshta.exe"
(ParentImage="*\winword.exe" OR
ParentImage="*\excel.exe" OR
ParentImage="*\powerpnt.exe" OR
ParentImage="*\outlook.exe" OR
ParentImage="*\wscript.exe" OR
ParentImage="*\cscript.exe" OR
ParentImage="*\explorer.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 3 — Mshta Executing Content from Suspicious Paths

This query detects mshta executing content from temporary or user-writable directories which are commonly used to stage malicious HTA files.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\mshta.exe"
(CommandLine="*\temp\*" OR
CommandLine="*\tmp\*" OR
CommandLine="*\appdata\*" OR
CommandLine="*\programdata\*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- Legitimate mshta usage is relatively rare in most enterprise environments outside of specific legacy applications — any hit warrants investigation
- `explorer.exe` is included as a parent process in Query 2 but may generate more noise than the other parent processes listed — can be removed if volume is too high in your environment
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
