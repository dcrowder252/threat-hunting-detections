# Certutil.exe Abuse — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/08/30
**MITRE ATT&CK:** T1105, T1140
**Reference:** https://attack.mitre.org/techniques/T1105/

---

## Query 1 — Certutil Download Cradle

This query detects certutil invocations containing flags associated with downloading files from remote locations. Legitimate certutil usage rarely includes these flags outside of specific PKI management scenarios.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /certutil\.exe$/i
| CommandLine = /(-urlcache|-split)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 2 — Certutil Encode and Decode Activity

This query detects certutil invocations used to encode or decode file content — a common technique for obfuscating payloads delivered through other means.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /certutil\.exe$/i
| CommandLine = /(-decode|-encode|-decodehex)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 3 — Certutil Spawned by Suspicious Parent Process

This query detects certutil spawned by parent processes commonly associated with phishing-based initial access including Office applications and scripting engines.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /certutil\.exe$/i
| ParentBaseFileName = /(winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|mshta\.exe|wscript\.exe|cscript\.exe|explorer\.exe)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- All three queries can be combined using OR logic if a single broad search is preferred — separating them allows for more granular tuning per technique
- `explorer.exe` is included as a parent process but may generate more noise than the other parent processes listed — users launching certutil through Explorer for legitimate reasons is not uncommon and can be removed from the regex if volume is too high in your environment
