# Regsvr32.exe Abuse — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/08/30
**MITRE ATT&CK:** T1218.010
**Reference:** https://attack.mitre.org/techniques/T1218/010/

---

## Query 1 — Regsvr32 Scriptlet Execution (Squiblydoo)

This query detects regsvr32 invocations using the /s /n /i flag combination commonly associated with the Squiblydoo technique for executing COM scriptlets. This combination is rarely observed in legitimate software installation activity.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\regsvr32.exe"
CommandLine="*/s*" CommandLine="*/n*" CommandLine="*/i*"
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 2 — Regsvr32 Loading Remote Content

This query detects regsvr32 invocations referencing remote URLs indicating attempts to load remotely hosted COM scriptlets.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\regsvr32.exe"
(CommandLine="*http://*" OR CommandLine="*https://*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 3 — Regsvr32 Loading SCT Files

This query detects regsvr32 invocations referencing COM scriptlet files with the .sct extension which are commonly used in LOLBin abuse scenarios.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\regsvr32.exe"
CommandLine="*.sct*"
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 4 — Regsvr32 Spawned by Suspicious Parent Process

This query detects regsvr32 spawned by parent processes commonly associated with phishing-based initial access. Regsvr32 being launched by Office applications or scripting engines is a strong indicator of malicious document execution.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\regsvr32.exe"
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
- Query 1 targets the Squiblydoo technique specifically — the `/s /n /i` flag combination is the key indicator and is rarely observed in legitimate regsvr32 usage
- Legitimate regsvr32 usage typically involves registering DLL files during software installation and rarely uses the flags or file types targeted by these queries
- `explorer.exe` is included as a parent process in Query 4 but may generate more noise than the other parent processes listed — can be removed if volume is too high in your environment
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
