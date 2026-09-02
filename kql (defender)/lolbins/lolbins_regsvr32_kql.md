# Regsvr32.exe Abuse — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/08/30
**MITRE ATT&CK:** T1218.010
**Reference:** https://attack.mitre.org/techniques/T1218/010/

---

## Query 1 — Regsvr32 Scriptlet Execution (Squiblydoo)

This query detects regsvr32 invocations using the /s /n /i flag combination commonly associated with the Squiblydoo technique for executing COM scriptlets. This combination is rarely observed in legitimate software installation activity.

```kql
DeviceProcessEvents
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has "/s"
    and ProcessCommandLine has "/n"
    and ProcessCommandLine has "/i"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 2 — Regsvr32 Loading Remote Content

This query detects regsvr32 invocations referencing remote URLs indicating attempts to load remotely hosted COM scriptlets.

```kql
DeviceProcessEvents
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has_any ("http://", "https://")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 3 — Regsvr32 Loading SCT Files

This query detects regsvr32 invocations referencing COM scriptlet files with the .sct extension which are commonly used in LOLBin abuse scenarios.

```kql
DeviceProcessEvents
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has ".sct"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 4 — Regsvr32 Spawned by Suspicious Parent Process

This query detects regsvr32 spawned by parent processes commonly associated with phishing-based initial access. Regsvr32 being launched by Office applications or scripting engines is a strong indicator of malicious document execution.

```kql
DeviceProcessEvents
| where FileName =~ "regsvr32.exe"
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
- Query 1 targets the Squiblydoo technique specifically — the `/s /n /i` flag combination is the key indicator and is rarely observed in legitimate regsvr32 usage
- The three consecutive `has` conditions in Query 1 act as an AND — all three flags must be present in the command line
- Legitimate regsvr32 usage typically involves registering DLL files during software installation and rarely uses the flags or file types targeted by these queries
- `explorer.exe` is included as a parent process in Query 4 but may generate more noise than the other parent processes listed — can be removed if volume is too high in your environment
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
