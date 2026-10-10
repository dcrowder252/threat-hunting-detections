# Bitsadmin.exe Abuse — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/09/05
**MITRE ATT&CK:** T1197
**Reference:** https://attack.mitre.org/techniques/T1197/

---

## Query 1 — Bitsadmin Job Creation with External URL

This query detects bitsadmin invocations creating BITS transfer jobs referencing external URLs. Legitimate bitsadmin usage in enterprise environments is relatively uncommon and any invocation referencing external URLs outside of approved software deployment processes warrants investigation.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /bitsadmin\.exe$/i
| CommandLine = /(\/transfer|\/create|\/addfile)/i
| CommandLine = /(http:\/\/|https:\/\/)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 2 — Bitsadmin Downloading to Suspicious Paths

This query detects bitsadmin invocations downloading files to temporary directories or user-writable locations commonly used to stage malicious payloads.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /bitsadmin\.exe$/i
| CommandLine = /(\/transfer|\/addfile)/i
| CommandLine = /(\\temp\\|\\tmp\\|\\appdata\\|\\programdata\\)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Query 3 — Bitsadmin Spawned by Suspicious Parent Process

This query detects bitsadmin spawned by parent processes not typically associated with legitimate BITS job management. Bitsadmin being launched by scripting engines or Office applications is a strong indicator of malicious activity.

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /bitsadmin\.exe$/i
| ParentBaseFileName = /(winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|mshta\.exe|wscript\.exe|cscript\.exe|explorer\.exe|powershell\.exe|cmd\.exe)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- Consecutive filter lines in Queries 1 and 2 act as an AND condition — both patterns must match
- Legitimate bitsadmin usage in enterprise environments is relatively uncommon — any results outside of approved software deployment workflows warrant investigation
- `explorer.exe`, `powershell.exe`, and `cmd.exe` are included in Query 3 as parent processes — these may generate some noise depending on the environment and can be removed individually if needed
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
- By default CrowdStrike LogScale caps results at 200 — to increase this limit add a `limit` parameter inside the table command with a value up to 20,000. Example: `| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName], sortby=@timestamp, order=desc, limit=10000)`