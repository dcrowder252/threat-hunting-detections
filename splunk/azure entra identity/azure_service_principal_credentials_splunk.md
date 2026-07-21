# Service Principal and Application Credential Additions — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/17
**MITRE ATT&CK:** T1098.001
**Reference:** https://attack.mitre.org/techniques/T1098/001/

---

## Query

```spl
index=<your_index> sourcetype="azure:monitor:aad"
(operationName="Add service principal credentials" OR
operationName="Update application – Certificates and secrets management" OR
operationName="Add password credential to service principal" OR
operationName="Add key credential to service principal")
status="success"
| spath path=properties.targetResources{}.displayName output=TargetApplication
| table _time, user, TargetApplication, operationName, status, callerIpAddress
| rename user as PerformedBy, callerIpAddress as IPAddress
| sort - _time
```

---

## Notes

- Adjust index value to match your environment
- Sourcetype validated as `azure:monitor:aad` — adjust if your environment uses a different sourcetype for Azure AD audit logs
- `operationName` is lowercase — field names in Azure AD logs are case sensitive in Splunk
- `status="success"` filters out failed attempts — only successful credential additions are returned — however running a separate search looking for high volumes of failed credential addition attempts may also be worth investigating as it could indicate an attacker probing for access
- `user` contains the UPN of the account that performed the credential addition
- `TargetApplication` identifies the application or service principal that was modified
- `spath` extracts the application name from the nested JSON structure under `properties.targetResources{}.displayName`
- Unlike user sessions which expire application credentials remain valid until explicitly revoked — making this a high priority detection
- Any credential addition outside of an approved change management window should be investigated promptly
- The nested JSON structure may not be present in all tenants depending on how Azure AD logs are ingested and normalized — some ingestion methods flatten these fields at index time
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting

---

## Related Defender Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Microsoft Defender for Cloud Apps — Suspicious credential addition to an OAuth app
- Entra ID Protection — Suspicious service principal activity
- Entra ID Protection — Impossible travel
