# Scheduled Task Created — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/05/24
**MITRE ATT&CK:** T1053.005
**Reference:** https://attack.mitre.org/techniques/T1053/005/

---

## Query

```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, AdditionalFields
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- `ScheduledTaskCreated` is the ActionType generated when a new scheduled task is registered
- `AdditionalFields` contains the task name, action, and configuration details and is the most valuable field for understanding what the task is configured to do
- `InitiatingProcessAccountName` and `InitiatingProcessAccountDomain` identify the account that created the task
- Pay particular attention to tasks configured to run as SYSTEM or referencing unusual execution paths or encoded commands
- EventID 4698 requires the Audit Other Object Access Events policy to be enabled — this is not configured by default on all Windows systems
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known scheduled task baselines before alerting
