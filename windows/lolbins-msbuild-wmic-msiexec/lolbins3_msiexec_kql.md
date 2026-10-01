# Msiexec.exe Abuse — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/09/29
**MITRE ATT&CK:** T1218.007
**Reference:** https://attack.mitre.org/techniques/T1218/007/

---

## Query 1 — Msiexec Executing Remote Package

This query detects msiexec invocations where the /i flag is followed by a remote URL rather than a local file path. Legitimate software deployment via msiexec typically references local paths or internal network shares rather than external web URLs.

```kql
DeviceProcessEvents
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has "/i"
| where ProcessCommandLine has_any ("http://", "https://")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 2 — Msiexec Silent Execution from Suspicious Path

This query detects msiexec invocations using silent execution flags alongside references to temporary directories or user-writable locations commonly used to stage malicious packages.

```kql
DeviceProcessEvents
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has_any ("/quiet", "/q")
| where ProcessCommandLine has_any (@"\temp\", @"\tmp\", @"\appdata\", @"\programdata\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 3 — Msiexec Spawned by Suspicious Parent Process

This query detects msiexec spawned by parent processes commonly associated with phishing-based initial access. Legitimate software deployment typically involves dedicated deployment tool parent processes rather than Office applications or scripting engines.

```kql
DeviceProcessEvents
| where FileName =~ "msiexec.exe"
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "explorer.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- The two consecutive `has` conditions in Query 1 act as an AND — both patterns must be present in the command line
- Query 2 may generate significant noise in environments using patch management tools such as PatchMyPC, SCCM, or Ivanti as these tools commonly invoke msiexec silently and write logs to temp directories as part of normal patching operations — exclude known patch management tool names from the ProcessCommandLine filter to reduce noise
- `explorer.exe` is included as a parent process in Query 3 but may generate more noise than the other parent processes listed — users launching installers directly through Explorer is common and can be removed if volume is too high in your environment
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
