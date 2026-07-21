# Illicit Consent Grant Activity — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/17
**MITRE ATT&CK:** T1528
**Reference:** https://attack.mitre.org/techniques/T1528/

---

## Query

> This is a baseline query returning all consent grant activity — review results against your approved application inventory to identify unauthorized grants.

```spl
index=<your_index> sourcetype="azure:monitor:aad"
operationName="Consent to application"
status="success"
| spath path=properties.targetResources{}.displayName output=AppName
| table _time, user, AppName, operationName, status, callerIpAddress
| rename user as PerformedBy, callerIpAddress as IPAddress
| sort - _time
```

---

## High Privilege Scope Filter

The query below narrows results to consent grants requesting access to sensitive scopes commonly abused in illicit consent grant attacks — adjust the scope list based on your environment and approved applications.

```spl
index=<your_index> sourcetype="azure:monitor:aad"
operationName="Consent to application"
status="success"
| spath path=properties.targetResources{}.displayName output=AppName
| spath path=properties.targetResources{}.modifiedProperties{} output=ModProps
| mvexpand ModProps
| spath input=ModProps path=displayName output=PropName
| spath input=ModProps path=newValue output=PropValue
| where PropName="ConsentAction.Permissions"
| where (like(PropValue, "%Mail.Read%") OR
    like(PropValue, "%Mail.ReadWrite%") OR
    like(PropValue, "%Mail.Send%") OR
    like(PropValue, "%Files.ReadWrite.All%") OR
    like(PropValue, "%Directory.ReadWrite.All%") OR
    like(PropValue, "%User.ReadWrite.All%") OR
    like(PropValue, "%Contacts.ReadWrite%") OR
    like(PropValue, "%MailboxSettings.ReadWrite%"))
| table _time, user, AppName, PropValue, operationName, status, callerIpAddress
| rename user as PerformedBy, PropValue as Permissions, callerIpAddress as IPAddress
| sort - _time
```

---

## Notes

- Adjust index value to match your environment
- Sourcetype validated as `azure:monitor:aad` — adjust if your environment uses a different sourcetype for Azure AD audit logs
- `operationName` is lowercase — field names in Azure AD logs are case sensitive in Splunk
- `status="success"` filters out failed consent attempts — only successful grants are returned
- `user` contains the UPN of the account that granted consent
- `callerIpAddress` is an already extracted field containing the IP address of the request
- `spath` extracts the application name and requested permissions from the nested JSON structure
- `mvexpand` flattens the modified properties array so each element can be evaluated individually
- The permissions scope is stored in the modified properties element where `displayName="ConsentAction.Permissions"` — the `newValue` of that element contains the full permissions string including consent type and scope names
- The sensitive scope list is not exhaustive — add or remove scopes based on your organization's approved application inventory
- The nested JSON structure may not be present in all tenants depending on how Azure AD logs are ingested and normalized — some ingestion methods flatten these fields at index time
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting

---

## Related Defender Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Microsoft Defender for Cloud Apps — OAuth app with suspicious attributes
- Microsoft Defender for Cloud Apps — Misleading OAuth app name
- Microsoft Defender for Cloud Apps — OAuth app with suspicious redirect URL
- Entra ID Protection — Suspicious application consent
- Entra ID Protection — Impossible travel
