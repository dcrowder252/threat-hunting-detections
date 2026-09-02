# Mshta.exe Abuse — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/08/30
**MITRE ATT&CK:** T1218.005
**Reference:** https://attack.mitre.org/techniques/T1218/005/

---

## Query 1 — Mshta Executing Remote Content

This query detects mshta invocations referencing remote URLs in the command-line arguments indicating execution of remotely hosted HTML Application content. Legitimate mshta usage typically involves locally installed HTA files and rarely references external URLs.

```kql
DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("http://", "https://", @"\\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 2 — Mshta Spawned by Suspicious Parent Process

This query detects mshta spawned by parent processes commonly associated with phishing-based initial access. Mshta being launched by Office applications or scripting engines is a strong indicator of a malicious document or file execution.

```kql
DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "wscript.exe",
    "cscript.exe",
    "explorer.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 3 — Mshta Executing Content from Suspicious Paths

This query detects mshta executing content from temporary or user-writable directories which are commonly used to stage malicious HTA files.

```kql
DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any (@"\temp\", @"\tmp\", @"\appdata\", @"\programdata\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Legitimate mshta usage is relatively rare in most enterprise environments outside of specific legacy applications — any hit warrants investigation
- `explorer.exe` is included as a parent process in Query 2 but may generate more noise than the other parent processes listed — can be removed if volume is too high in your environment
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
