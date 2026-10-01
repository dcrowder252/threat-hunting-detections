# Msiexec.exe Abuse — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/09/29
**MITRE ATT&CK:** T1218.007
**Reference:** https://attack.mitre.org/techniques/T1218/007/

---

## Query 1 — Msiexec Executing Remote Package

This query detects msiexec invocations where the /i flag is followed by a remote URL rather than a local file path. Legitimate software deployment via msiexec typically references local paths or internal network shares rather than external web URLs.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /msiexec\.exe$/i
| CommandLine = /\/i\s+(http:\/\/|https:\/\/)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 2 — Msiexec Silent Execution from Suspicious Path

This query detects msiexec invocations using silent execution flags alongside references to temporary directories or user-writable locations commonly used to stage malicious packages.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /msiexec\.exe$/i
| CommandLine = /(\/quiet|\/q)/i
| CommandLine = /(\\temp\\|\\tmp\\|\\appdata\\|\\programdata\\)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 3 — Msiexec Spawned by Suspicious Parent Process

This query detects msiexec spawned by parent processes commonly associated with phishing-based initial access. Legitimate software deployment typically involves dedicated deployment tool parent processes rather than Office applications or scripting engines.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /msiexec\.exe$/i
| ParentBaseFileName = /(winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|mshta\.exe|wscript\.exe|cscript\.exe|explorer\.exe)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- Consecutive filter lines in Query 2 act as an AND condition — both patterns must match
- Query 2 may generate significant noise in environments using patch management tools such as PatchMyPC, SCCM, or Ivanti as these tools commonly invoke msiexec silently and write logs to temp directories as part of normal patching operations — exclude known patch management tool names from the CommandLine filter to reduce noise
- `explorer.exe` is included as a parent process in Query 3 but may generate more noise than the other parent processes listed — users launching installers directly through Explorer is common and can be removed if volume is too high in your environment
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
