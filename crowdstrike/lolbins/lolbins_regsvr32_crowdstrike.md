# Regsvr32.exe Abuse — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/08/30
**MITRE ATT&CK:** T1218.010
**Reference:** https://attack.mitre.org/techniques/T1218/010/

---

## Query 1 — Regsvr32 Scriptlet Execution (Squiblydoo)

This query detects regsvr32 invocations using the /s /n /i flag combination commonly associated with the Squiblydoo technique for executing COM scriptlets. This combination is rarely observed in legitimate software installation activity.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /regsvr32\.exe$/i
| CommandLine = /\/s.*\/n.*\/i/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 2 — Regsvr32 Loading Remote Content

This query detects regsvr32 invocations referencing remote URLs indicating attempts to load remotely hosted COM scriptlets.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /regsvr32\.exe$/i
| CommandLine = /(http:\/\/|https:\/\/)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 3 — Regsvr32 Loading SCT Files

This query detects regsvr32 invocations referencing COM scriptlet files with the .sct extension which are commonly used in LOLBin abuse scenarios.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /regsvr32\.exe$/i
| CommandLine = /\.sct/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 4 — Regsvr32 Spawned by Suspicious Parent Process

This query detects regsvr32 spawned by parent processes commonly associated with phishing-based initial access. Regsvr32 being launched by Office applications or scripting engines is a strong indicator of malicious document execution.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /regsvr32\.exe$/i
| ParentBaseFileName = /(winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|mshta\.exe|wscript\.exe|cscript\.exe|explorer\.exe)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- Query 1 targets the Squiblydoo technique specifically — the `/s /n /i` flag combination is the key indicator
- `explorer.exe` is included as a parent process but may generate more noise than the other parent processes listed — can be removed from the regex if volume is too high in your environment
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
