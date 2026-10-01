# Wmic.exe Abuse — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/09/29
**MITRE ATT&CK:** T1047
**Reference:** https://attack.mitre.org/techniques/T1047/

---

## Query 1 — Wmic Process Call Create

This query detects wmic invocations using the process call create method to execute processes locally or on remote systems. This capability is rarely used in legitimate administrative scenarios outside of specific management frameworks and is a common lateral movement and execution technique.

```kql
DeviceProcessEvents
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has "process"
| where ProcessCommandLine has "call"
| where ProcessCommandLine has "create"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 2 — Wmic Spawning Suspicious Child Process

This query detects processes spawned as children of wmic — a common technique used to obscure the origin of malicious execution by interposing wmic between the initial trigger and the ultimate payload.

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmic.exe"
| where FileName in~ (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "certutil.exe",
    "bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 3 — Wmic Querying Security Software

This query detects wmic invocations querying installed security software or antivirus products — a common reconnaissance technique used by attackers to understand what security controls are present before attempting to disable or evade them.

```kql
DeviceProcessEvents
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has_any (
    "AntiVirusProduct",
    "FirewallProduct",
    "AntiSpywareProduct",
    "AntiMalwareProduct",
    "SecurityCenter")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- As of the September 2026 Security Update wmic.exe has been removed from Windows 11 versions 24H2 and 25H2 — detection coverage remains important for environments running older Windows versions where wmic.exe is still present
- Query 1 uses three consecutive `has` conditions which act as an AND — all three terms must be present in the command line
- Query 2 monitors for wmic as the initiating process rather than the primary process — pay attention to which field is being filtered
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
