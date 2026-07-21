# Privileged Role Assignments — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/17
**MITRE ATT&CK:** T1098.003
**Reference:** https://attack.mitre.org/techniques/T1098/003/

---

## Query

```spl
index=<your_index> sourcetype="azure:monitor:aad"
(operationName="Add member to role" OR
operationName="Add eligible member to role")
| spath path=properties.targetResources{}.modifiedProperties{}.newValue output=AssignedRole
| spath path=properties.targetResources{}.userPrincipalName output=ElevatedUser
| mvexpand AssignedRole
| where NOT like(AssignedRole, "%-%-%-%-%")
| where like(AssignedRole, "% %")
| where status="success"
| search AssignedRole IN (
    "*Global Administrator*",
    "*Application Administrator*",
    "*Privileged Role Administrator*",
    "*Security Administrator*",
    "*Exchange Administrator*",
    "*SharePoint Administrator*",
    "*User Administrator*",
    "*Hybrid Identity Administrator*",
    "*Cloud Application Administrator*")
| table _time, user, ElevatedUser, AssignedRole, operationName, status
| rename user as PerformedBy
| sort - _time
```

---

## Notes

- Adjust index value to match your environment
- Sourcetype validated as `azure:monitor:aad` — adjust if your environment uses a different sourcetype for Azure AD audit logs
- `operationName` is lowercase — field names in Azure AD logs are case sensitive in Splunk
- `user` contains the UPN of the account that performed the role assignment
- `ElevatedUser` contains the UPN of the account that received the role — pay particular attention to accounts being elevated that have no prior administrative history or that have recently exhibited other suspicious activity
- `spath` extracts role values from the nested JSON structure under `properties.targetResources{}.modifiedProperties{}.newValue`
- `mvexpand` flattens the extracted array so each value appears as a separate row
- The first `where` clause filters out GUIDs by excluding values containing four or more hyphens
- The second `where` clause filters out short role names by keeping only values containing a space — leaving clean friendly display names only
- Only successful role assignments are returned — failed attempts are filtered out via `where status="success"` — however running a separate search looking for high volumes of failed role assignment attempts may also be worth investigating as it could indicate an attacker probing for privilege escalation opportunities
- Authentication Administrator has been intentionally excluded from the role list as it can generate significant volume in large organizations — add it back if relevant to your environment
- The sensitive roles list is not exhaustive — add or remove roles based on your organization's administrative structure and risk tolerance
- The nested JSON structure under `properties.targetResources{}` may not be present in all tenants depending on how Azure AD logs are ingested and normalized — some ingestion methods flatten these fields at index time, in which case the `spath` extraction may need to be adjusted or removed
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Any role assignment outside of an approved change management process should be investigated promptly
- Review results against known administrative baselines before alerting

---

## Related Defender Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Entra ID Protection — Suspicious privileged role assignment
- Microsoft Defender for Cloud Apps — Unusual administrative activity
- Entra ID Protection — Impossible travel
