# Wscript.exe and Cscript.exe Abuse — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/09/05
**MITRE ATT&CK:** T1059.005, T1059.007
**Reference:** https://attack.mitre.org/techniques/T1059/005/

---

## Query 1 — Wscript or Cscript Executing Scripts from Suspicious Paths

This query detects wscript or cscript executing script files from temporary directories or user-writable locations commonly used to stage malicious scripts delivered through phishing or drive-by download activity.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /(wscript\.exe|cscript\.exe)$/i
| CommandLine = /(\\temp\\|\\tmp\\|\\appdata\\|\\programdata\\|\\downloads\\)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 2 — Wscript or Cscript Executing Suspicious Script Extensions

This query detects wscript or cscript executing encoded or obfuscated script file types that are less commonly used in legitimate administrative scenarios.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /(wscript\.exe|cscript\.exe)$/i
| CommandLine = /(\.vbe|\.jse|\.wsf|\.wsh)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 3 — Wscript or Cscript Spawned by Suspicious Parent Process

This query detects wscript or cscript spawned by parent processes commonly associated with phishing-based initial access. Script Host engines being launched by Office applications or browser processes is a strong indicator of malicious document or file execution.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /(wscript\.exe|cscript\.exe)$/i
| ParentBaseFileName = /(winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|mshta\.exe|explorer\.exe|chrome\.exe|msedge\.exe|firefox\.exe|iexplore\.exe)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- Both `wscript.exe` and `cscript.exe` are covered in all queries — they provide equivalent scripting capability and are interchangeable from an attacker perspective
- Query 2 focuses on encoded script extensions — `.vbe` is an encoded VBScript file and `.jse` is an encoded JScript file — these are less commonly used in legitimate automation and warrant investigation
- `explorer.exe` is included as a parent process in Query 3 but may generate more noise than the other parent processes listed — can be removed if volume is too high in your environment
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
- By default CrowdStrike LogScale caps results at 200 — to increase this limit add a `limit` parameter inside the table command with a value up to 20,000. Example: `| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName], sortby=@timestamp, order=desc, limit=10000)`