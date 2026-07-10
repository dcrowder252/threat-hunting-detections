# Linux Bash History Manipulation — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/25
**MITRE ATT&CK:** T1070.003
**Reference:** https://attack.mitre.org/techniques/T1070/003/

---

## Query

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where ProcessCommandLine has_any (
    "history -c",
    "HISTSIZE=0",
    "HISTFILESIZE=0",
    "unset HISTFILE",
    "HISTFILE=/dev/null",
    "rm .*\.bash_history",
    "truncate -s 0 .*\.bash_history",
    "shred .*\.bash_history"
)
| where not(ProcessCommandLine has "locate")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- The `DeviceInfo` subquery filters results to Linux endpoints only
- The query consolidates multiple bash history tampering techniques into a single search — clearing, unsetting, redirecting, deleting, truncating, and shredding `.bash_history`
- `locate` is explicitly excluded as it commonly searches for `.bash_history` files as part of normal filesystem indexing activity and generates significant false positive noise
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- MDE Linux coverage requires Microsoft Defender for Endpoint to be deployed on Linux endpoints
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
