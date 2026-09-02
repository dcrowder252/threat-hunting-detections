# Mshta.exe Abuse — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/08/30
**MITRE ATT&CK:** T1218.005
**Reference:** https://attack.mitre.org/techniques/T1218/005/

---

## Query 1 — Mshta Executing Remote Content

This query detects mshta invocations referencing remote URLs in the command-line arguments indicating execution of remotely hosted HTML Application content. Legitimate mshta usage typically involves locally installed HTA files and rarely references external URLs.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /mshta\.exe$/i
| CommandLine = /(http:\/\/|https:\/\/|\\\\)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 2 — Mshta Spawned by Suspicious Parent Process

This query detects mshta spawned by parent processes commonly associated with phishing-based initial access. Mshta being launched by Office applications or scripting engines is a strong indicator of a malicious document or file execution.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /mshta\.exe$/i
| ParentBaseFileName = /(winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|wscript\.exe|cscript\.exe|explorer\.exe)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 3 — Mshta Executing Content from Suspicious Paths

This query detects mshta executing content from temporary or user-writable directories which are commonly used to stage malicious HTA files.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /mshta\.exe$/i
| CommandLine = /(\\temp\\|\\tmp\\|\\appdata\\|\\programdata\\)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- `explorer.exe` is included as a parent process but may generate more noise than the other parent processes listed — can be removed from the regex if volume is too high in your environment
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
