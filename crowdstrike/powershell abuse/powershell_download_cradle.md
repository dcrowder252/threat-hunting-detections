# PowerShell Download Cradle Execution — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/05/04
**MITRE ATT&CK:** T1059.001, T1105, T1027
**Reference:** https://attack.mitre.org/techniques/T1059/001/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /(powershell\.exe|pwsh\.exe)$/i
| CommandLine = /(IEX|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|WebRequest|curl|wget)/i
| table(@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=@timestamp, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- The regex covers all common download cradle patterns in a single clean expression
- `curl` and `wget` are included as PowerShell 7 supports both natively
- `ParentBaseFileName` surfaces the parent process for additional triage context
- These patterns should be investigated in context — presence alongside encoded commands or unusual parent processes significantly increases likelihood of malicious activity
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
