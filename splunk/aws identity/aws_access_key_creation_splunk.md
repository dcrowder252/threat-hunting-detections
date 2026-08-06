# IAM Access Key Creation — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/28
**MITRE ATT&CK:** T1098.001
**Reference:** https://attack.mitre.org/techniques/T1098/001/

---

## Query

```spl
index=<your_index> sourcetype="aws:cloudtrail"
eventName="CreateAccessKey"
errorCode=success
| spath path=requestParameters.userName output=TargetUser
| table _time, userIdentity.sessionContext.sessionIssuer.userName, TargetUser, eventName, sourceIPAddress, awsRegion, userAgent
| rename userIdentity.sessionContext.sessionIssuer.userName as PerformedBy, sourceIPAddress as IPAddress
| sort - _time
```

---

## Notes

- Adjust index value to match your environment
- Sourcetype for AWS CloudTrail logs in Splunk is typically `aws:cloudtrail` — adjust if your environment uses a different sourcetype
- `errorCode=success` filters to successful access key creation only — remove to include failed attempts
- `userIdentity.sessionContext.sessionIssuer.userName` identifies the account that created the key
- These may differ when an administrator creates a key for another user — pay particular attention when `PerformedBy` and `TargetUser` are different accounts
- `spath` is used to extract the target username from the nested `requestParameters` JSON — the nested JSON structure may not be present in all tenants depending on how CloudTrail logs are ingested and normalized
- Unlike console passwords which require MFA, access keys provide direct API access without additional authentication — making this a high priority persistence detection
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting

---

## Related AWS Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your AWS security tooling and licensing tier:

- Amazon GuardDuty — IAMUser/AnomalousBehavior
- AWS Security Hub — IAM access key creation findings
