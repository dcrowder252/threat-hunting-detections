# Msiexec.exe Abuse — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/09/29
**MITRE ATT&CK:** T1218.007
**Reference:** https://attack.mitre.org/techniques/T1218/007/

---

## Query 1 — Msiexec Executing Remote Package

This query detects msiexec invocations where the /i flag is followed by a remote URL rather than a local file path. Legitimate software deployment via msiexec typically references local paths or internal network shares rather than external web URLs.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\msiexec.exe"
(CommandLine="*/i http://*" OR CommandLine="*/i https://*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 2 — Msiexec Silent Execution from Suspicious Path

This query detects msiexec invocations using silent execution flags alongside references to temporary directories or user-writable locations commonly used to stage malicious packages.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\msiexec.exe"
(CommandLine="*/quiet*" OR CommandLine="*/q*")
(CommandLine="*\temp\*" OR
CommandLine="*\tmp\*" OR
CommandLine="*\appdata\*" OR
CommandLine="*\programdata\*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 3 — Msiexec Spawned by Suspicious Parent Process

This query detects msiexec spawned by parent processes commonly associated with phishing-based initial access. Legitimate software deployment typically involves dedicated deployment tool parent processes rather than Office applications or scripting engines.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\msiexec.exe"
(ParentImage="*\winword.exe" OR
ParentImage="*\excel.exe" OR
ParentImage="*\powerpnt.exe" OR
ParentImage="*\outlook.exe" OR
ParentImage="*\mshta.exe" OR
ParentImage="*\wscript.exe" OR
ParentImage="*\cscript.exe" OR
ParentImage="*\explorer.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- Query 2 may generate significant noise in environments using patch management tools such as PatchMyPC, SCCM, or Ivanti as these tools commonly invoke msiexec silently and write logs to temp directories as part of normal patching operations — exclude known patch management tool names from the CommandLine filter to reduce noise
- `explorer.exe` is included as a parent process in Query 3 but may generate more noise than the other parent processes listed — users launching installers directly through Explorer is common and can be removed if volume is too high in your environment
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
