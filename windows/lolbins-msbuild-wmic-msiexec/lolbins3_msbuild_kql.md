# Msbuild.exe Abuse — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/09/29
**MITRE ATT&CK:** T1127.001
**Reference:** https://attack.mitre.org/techniques/T1127/001/

---

## Query 1 — Msbuild Executing Project Files from Suspicious Paths

This query detects msbuild invocations referencing project files in temporary directories or user-writable locations. Legitimate msbuild usage references project files in standard development directories rather than temporary or user profile locations.

```kql
DeviceProcessEvents
| where FileName =~ "msbuild.exe"
| where FolderPath !contains "Microsoft Visual Studio"
| where ProcessCommandLine has_any (@"\temp\", @"\tmp\", @"\appdata\", @"\programdata\", @"\users\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 2 — Msbuild Executing Project Files from Remote Locations

This query detects msbuild invocations referencing project files from remote locations including external URLs or UNC paths — a technique used to execute malicious inline code from attacker-controlled infrastructure while keeping the payload off the local filesystem.

```kql
DeviceProcessEvents
| where FileName =~ "msbuild.exe"
| where ProcessCommandLine has_any ("http://", "https://", @"\\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 3 — Msbuild Spawned by Suspicious Parent Process

This query detects msbuild spawned by parent processes not typically associated with legitimate build activity. Msbuild being launched by Office applications, scripting engines, or other LOLBins is a strong indicator of malicious inline code execution.

```kql
DeviceProcessEvents
| where FileName =~ "msbuild.exe"
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "cmd.exe",
    "powershell.exe",
    "explorer.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- `Microsoft Visual Studio` is excluded from Query 1 via the `FolderPath` field as Visual Studio regularly invokes msbuild from its installation directory for NuGet package restores and build operations that write to temp locations — this exclusion significantly reduces noise from legitimate developer activity
- `explorer.exe`, `cmd.exe`, and `powershell.exe` are included in Query 3 as parent processes — these may generate some noise depending on the environment and can be removed individually if needed
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
