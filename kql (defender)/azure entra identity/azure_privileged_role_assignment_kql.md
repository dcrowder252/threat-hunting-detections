# Privileged Role Assignments — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/14
**MITRE ATT&CK:** T1098.003
**Reference:** https://attack.mitre.org/techniques/T1098/003/

---

## Query

```kql
let SensitiveRoles = dynamic([
    "Global Administrator",
    "Application Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
    "Hybrid Identity Administrator",
    "Cloud Application Administrator"
]);
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "Add member to role",
    "Add eligible member to role"
)
| extend EventDetails = parse_json(RawEventData)
| extend
    AssignedRole = tostring(EventDetails.ModifiedProperties[0].NewValue),
    TargetUser = tostring(EventDetails.Target[0].ID)
| where AssignedRole has_any (SensitiveRoles)
| where RawEventData has "success"
| project
    Timestamp,
    PerformedBy = AccountUpn,
    TargetUser,
    AssignedRole,
    ActionType
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Table availability varies by tenant configuration and licensing — run `search * | distinct $table` in Advanced Hunting to confirm which tables are available in your environment before executing these queries
- Requires the `CloudAppEvents` table which is available with Microsoft Defender for Cloud Apps licensing
- Organizations using Microsoft Sentinel should use the `AuditLogs` table and filter on `OperationName` for "Add member to role" — adjust field names accordingly
- `PerformedBy` identifies the account that performed the role assignment — `TargetUser` identifies the account that received the role
- Authentication Administrator has been intentionally excluded from the role list as it can generate significant volume in large organizations — add it back if relevant to your environment
- The sensitive roles list is not exhaustive — add or remove roles based on your organization's administrative structure and risk tolerance
- Only successful role assignments are returned — failed attempts are filtered out — however running a separate query looking for high volumes of failed role assignment attempts may also be worth investigating as it could indicate an attacker probing for privilege escalation opportunities
- Pay particular attention to role assignments made to accounts with no prior administrative history or accounts that have recently exhibited other suspicious activity
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting

---

## Related Defender Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Entra ID Protection — Suspicious privileged role assignment
- Microsoft Defender for Cloud Apps — Unusual administrative activity
- Entra ID Protection — Impossible travel
