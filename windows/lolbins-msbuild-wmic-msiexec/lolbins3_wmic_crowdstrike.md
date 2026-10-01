# Wmic.exe Abuse — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/09/29
**MITRE ATT&CK:** T1047
**Reference:** https://attack.mitre.org/techniques/T1047/

---

## Query 1 — Wmic Process Call Create

This query detects wmic invocations using the process call create method to execute processes locally or on remote systems. This capability is rarely used in legitimate administrative scenarios outside of specific management frameworks and is a common lateral movement and execution technique.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /wmic\.exe$/i
| CommandLine = /process\s+call\s+create/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 2 — Wmic Spawning Suspicious Child Process

This query detects processes spawned as children of wmic — a common technique used to obscure the origin of malicious execution by interposing wmic between the initial trigger and the ultimate payload.

```kusto
#event_simpleName=ProcessRollup2
| ParentBaseFileName = /wmic\.exe$/i
| ImageFileName = /(powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe|msiexec\.exe|certutil\.exe|bitsadmin\.exe)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 3 — Wmic Querying Security Software

This query detects wmic invocations querying installed security software or antivirus products — a common reconnaissance technique used by attackers to understand what security controls are present before attempting to disable or evade them.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /wmic\.exe$/i
| CommandLine = /(AntiVirusProduct|FirewallProduct|AntiSpywareProduct|AntiMalwareProduct|SecurityCenter)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- As of the September 2026 Security Update wmic.exe has been removed from Windows 11 versions 24H2 and 25H2 — detection coverage remains important for environments running older Windows versions where wmic.exe is still present
- Query 2 monitors for wmic as a parent process rather than the primary process — pay attention to which field is being filtered
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
