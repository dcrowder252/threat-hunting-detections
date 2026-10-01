# Msbuild.exe Abuse — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/09/29
**MITRE ATT&CK:** T1127.001
**Reference:** https://attack.mitre.org/techniques/T1127/001/

---

## Query 1 — Msbuild Executing Project Files from Suspicious Paths

This query detects msbuild invocations referencing project files in temporary directories or user-writable locations. Legitimate msbuild usage references project files in standard development directories rather than temporary or user profile locations.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\msbuild.exe"
NOT Image="*\Microsoft Visual Studio\*"
(CommandLine="*\temp\*" OR
CommandLine="*\tmp\*" OR
CommandLine="*\appdata\*" OR
CommandLine="*\programdata\*" OR
CommandLine="*\users\*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 2 — Msbuild Executing Project Files from Remote Locations

This query detects msbuild invocations referencing project files from remote locations including external URLs or UNC paths — a technique used to execute malicious inline code from attacker-controlled infrastructure while keeping the payload off the local filesystem.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\msbuild.exe"
(CommandLine="*http://*" OR CommandLine="*https://*" OR CommandLine="*\\\\*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 3 — Msbuild Spawned by Suspicious Parent Process

This query detects msbuild spawned by parent processes not typically associated with legitimate build activity. Msbuild being launched by Office applications, scripting engines, or other LOLBins is a strong indicator of malicious inline code execution.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\msbuild.exe"
(ParentImage="*\winword.exe" OR
ParentImage="*\excel.exe" OR
ParentImage="*\powerpnt.exe" OR
ParentImage="*\outlook.exe" OR
ParentImage="*\mshta.exe" OR
ParentImage="*\wscript.exe" OR
ParentImage="*\cscript.exe" OR
ParentImage="*\cmd.exe" OR
ParentImage="*\powershell.exe" OR
ParentImage="*\explorer.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- `Microsoft Visual Studio` is excluded from Query 1 as Visual Studio regularly invokes msbuild from its installation directory for NuGet package restores and build operations that write to temp locations — this exclusion significantly reduces noise from legitimate developer activity while preserving coverage for malicious msbuild invocations from other locations
- `explorer.exe`, `cmd.exe`, and `powershell.exe` are included in Query 3 as parent processes — these may generate some noise depending on the environment and can be removed individually if needed
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
