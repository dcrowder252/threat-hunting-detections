# Linux Log File Truncation or Deletion — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/25
**MITRE ATT&CK:** T1070.002
**Reference:** https://attack.mitre.org/techniques/T1070/002/

---

## Query

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where ProcessCommandLine has_any (
    "truncate -s 0",
    "> /var/log/",
    ">> /var/log/"
)
or (ProcessCommandLine has "rm" and ProcessCommandLine has "/var/log/")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- The `DeviceInfo` subquery filters results to Linux endpoints only
- Both `>` and `>>` redirection operators are included — `>` overwrites file contents while `>>` appends and can be used to flood log files with junk data to obscure legitimate entries
- The `rm` condition is paired with `/var/log/` to avoid matching unrelated file deletions
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- MDE Linux coverage requires Microsoft Defender for Endpoint to be deployed on Linux endpoints
- Log rotation scripts may generate false positives — establish a baseline of approved log management activity before alerting
- Field names may vary across tenants — adjust as necessary for your environment
- This detection can be very noisy — if `>>` generates too much noise consider focusing on `>` only, or narrowing results by filtering on specific usernames known to perform legitimate log management
- Review results against known administrative baselines before alerting
