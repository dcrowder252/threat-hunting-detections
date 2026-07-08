# Reverse SSH Tunnel Established via SSH.exe — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1572, T1021.001
**Reference:** https://attack.mitre.org/techniques/T1572/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```kusto
#event_simpleName=ProcessRollup2
| ImageFileName = /ssh\.exe$/i
| CommandLine = /\s-R\s/i
| table(_time, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- `ProcessRollup2` is the standard CrowdStrike event for process creation
- The regex matches the `-R` flag with surrounding whitespace to avoid partial matches on other SSH arguments
- The `-R` flag indicates a reverse port forward — legitimate administrative use of this flag is rare on production systems
- Review the full command line for external IP addresses and port numbers to understand the tunnel destination
- `ParentBaseFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
