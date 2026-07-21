# Illicit Consent Grant Activity — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/14
**MITRE ATT&CK:** T1528
**Reference:** https://attack.mitre.org/techniques/T1528/

---

## Query

> This is a baseline query returning all consent grant activity — review results against your approved application inventory to identify unauthorized grants.

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType == "Consent to application"
| extend ConsentDetails = parse_json(RawEventData)
| extend
    GrantedBy = tostring(ConsentDetails.UserId),
    AppName = tostring(ConsentDetails.Target[0].ID),
    ModProps = ConsentDetails.ModifiedProperties
| mv-expand ModProps
| extend
    PropName = tostring(ModProps.displayName),
    PropValue = tostring(ModProps.newValue)
| where PropName == "ConsentAction.Permissions"
| project
    Timestamp,
    AccountUpn,
    AppName,
    GrantedBy,
    Permissions = PropValue,
    ActionType,
    IPAddress = callerIpAddress
| sort by Timestamp desc
```

---

## High Privilege Scope Filter

The query below narrows results to consent grants requesting access to sensitive scopes commonly abused in illicit consent grant attacks — adjust the scope list based on your environment and approved applications.

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType == "Consent to application"
| extend ConsentDetails = parse_json(RawEventData)
| extend
    GrantedBy = tostring(ConsentDetails.UserId),
    AppName = tostring(ConsentDetails.Target[0].ID),
    ModProps = ConsentDetails.ModifiedProperties
| mv-expand ModProps
| extend
    PropName = tostring(ModProps.displayName),
    PropValue = tostring(ModProps.newValue)
| where PropName == "ConsentAction.Permissions"
| where PropValue has_any (
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
    "Contacts.ReadWrite",
    "MailboxSettings.ReadWrite")
| project
    Timestamp,
    AccountUpn,
    AppName,
    GrantedBy,
    Permissions = PropValue,
    ActionType,
    IPAddress = callerIpAddress
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Table availability varies by tenant configuration and licensing — run `search * | distinct $table` in Advanced Hunting to confirm which tables are available in your environment before executing these queries
- Requires the `CloudAppEvents` table which is available with Microsoft Defender for Cloud Apps licensing
- Organizations using Microsoft Sentinel should use the `OfficeActivity` or `AuditLogs` table and adjust field names accordingly
- `callerIpAddress` is an already extracted field containing the IP address of the request
- `mv-expand` flattens the modified properties array so each element can be evaluated individually
- The permissions scope is stored in the modified properties element where `displayName="ConsentAction.Permissions"` — the `newValue` of that element contains the full permissions string including consent type and scope names
- The sensitive scope list is not exhaustive — add or remove scopes based on your organization's approved application inventory
- Pay particular attention to consent grants made by non-administrative users or grants to applications from unverified publishers
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting

---

## Related Defender Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Microsoft Defender for Cloud Apps — OAuth app with suspicious attributes
- Microsoft Defender for Cloud Apps — Misleading OAuth app name
- Microsoft Defender for Cloud Apps — OAuth app with suspicious redirect URL
- Entra ID Protection — Suspicious application consent
- Entra ID Protection — Impossible travel
