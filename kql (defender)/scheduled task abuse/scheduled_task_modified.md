# Scheduled Task Modified — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/24
**MITRE ATT&CK:** T1053.005, T1036
**Reference:** https://attack.mitre.org/techniques/T1053/005/

---

## Query

```kql
DeviceEvents
| where ActionType == "ScheduledTaskUpdated"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, AdditionalFields
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- `ScheduledTaskUpdated` is the ActionType generated when an existing scheduled task is modified
- `AdditionalFields` contains the updated task definition and should be reviewed for unexpected changes to task actions, triggers, or execution context
- `InitiatingProcessAccountName` and `InitiatingProcessAccountDomain` identify the account that modified the task
- Modifications made outside of known software deployment or maintenance windows should be treated as suspicious
- EventID 4702 requires the Audit Other Object Access Events policy to be enabled — this is not configured by default on all Windows systems
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known scheduled task baselines before alerting
