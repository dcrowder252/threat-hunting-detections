# Reverse SSH Tunnel Established via SSH.exe — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1572, T1021.001
**Reference:** https://attack.mitre.org/techniques/T1572/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```kql
DeviceProcessEvents
| where FileName =~ "ssh.exe"
| where ProcessCommandLine contains " -R "
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- The `-R` flag with surrounding spaces is intentional to avoid partial matches on other SSH arguments
- The `-R` flag indicates a reverse port forward — legitimate administrative use of this flag is rare on production systems
- Review the full command line for external IP addresses and port numbers to understand the tunnel destination
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
