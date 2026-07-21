# Service Principal and Application Credential Additions — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/14
**MITRE ATT&CK:** T1098.001
**Reference:** https://attack.mitre.org/techniques/T1098/001/

---

## Query

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "Add service principal credentials",
    "Update application – Certificates and secrets management",
    "Add password credential to service principal",
    "Add key credential to service principal"
)
| extend EventDetails = parse_json(RawEventData)
| extend
    TargetApp = tostring(EventDetails.Target[0].ID),
    CredentialType = tostring(EventDetails.ModifiedProperties)
| project
    Timestamp,
    PerformedBy = AccountUpn,
    TargetApplication = TargetApp,
    CredentialType,
    ActionType,
    IPAddress = callerIpAddress
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Table availability varies by tenant configuration and licensing — run `search * | distinct $table` in Advanced Hunting to confirm which tables are available in your environment before executing these queries
- Requires the `CloudAppEvents` table which is available with Microsoft Defender for Cloud Apps licensing
- Organizations using Microsoft Sentinel should use the `AuditLogs` table and filter on `OperationName` using the same operation names above — adjust field names accordingly
- Any credential addition outside of an approved change management window should be investigated promptly
- Pay particular attention to credential additions to high privilege applications such as those with Global Administrator or Application Administrator permissions
- `callerIpAddress` is an already extracted field containing the IP address of the initiating request — not always populated depending on how the operation was initiated
- Unlike user sessions which expire, application credentials remain valid until explicitly revoked — making this a high priority detection
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting

---

## Related Defender Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Microsoft Defender for Cloud Apps — Suspicious credential addition to an OAuth app
- Entra ID Protection — Suspicious service principal activity
- Entra ID Protection — Impossible travel
