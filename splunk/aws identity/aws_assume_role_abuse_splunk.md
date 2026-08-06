# Assumed Role Abuse — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/28
**MITRE ATT&CK:** T1548.005
**Reference:** https://attack.mitre.org/techniques/T1548/005/

---

## Query

```spl
index=<your_index> sourcetype="aws:cloudtrail"
eventName="AssumeRole"
errorCode=success
NOT userIdentity.type="AWSService"
| spath path=requestParameters.roleArn output=AssumedRole
| spath path=requestParameters.roleSessionName output=SessionName
| table _time, userName, userIdentity.type, AssumedRole, SessionName, sourceIPAddress, awsRegion, userAgent
| rename userName as PerformedBy, userIdentity.type as IdentityType, sourceIPAddress as IPAddress
| sort - _time
```

---

## Cross-Account AssumeRole Filter

The query below narrows results to cross-account role assumptions which are higher risk and warrant closer scrutiny — adjust the account ID to match your own AWS account to surface assumptions into external accounts.

```spl
index=<your_index> sourcetype="aws:cloudtrail"
eventName="AssumeRole"
errorCode=success
NOT userIdentity.type="AWSService"
| spath path=requestParameters.roleArn output=AssumedRole
| spath path=requestParameters.roleSessionName output=SessionName
| where NOT like(AssumedRole, "%::<your_account_id>:%")
| table _time, userName, userIdentity.type, AssumedRole, SessionName, sourceIPAddress, awsRegion
| rename userName as PerformedBy, userIdentity.type as IdentityType, sourceIPAddress as IPAddress
| sort - _time
```

---

## Notes

- Adjust index value to match your environment
- Sourcetype for AWS CloudTrail logs in Splunk is typically `aws:cloudtrail` — adjust if your environment uses a different sourcetype
- `errorCode=success` filters to successful role assumptions only — remove to include failed attempts
- `AWSService` is excluded as it represents AWS services calling other AWS services internally and generates significant noise — the remaining identity types and their typical use cases are:
  - `IAMUser` — a human IAM user assuming a role — highest interest from an attacker perspective
  - `AWSAccount` — a cross-account role assumption — potentially interesting depending on environment
  - `AssumedRole` — a chain assumption where an already assumed role assumes another role — can be noisy but worth reviewing
- After filtering out `AWSService` the performing user identity is stored in `userName` — when `userIdentity.type` is `AWSService` the identity is instead stored in `userIdentity.sessionContext.sessionIssuer`
- `AssumedRole` contains the ARN of the role being assumed — the account ID embedded in the ARN identifies whether this is a same-account or cross-account assumption
- `AssumeRole` is used frequently in legitimate automation and service authentication — establishing a baseline of normal role assumption patterns is essential before alerting
- Replace `<your_account_id>` in the cross-account filter with your actual AWS account ID
- `spath` is used to extract role details from the nested `requestParameters` JSON — the nested JSON structure may not be present in all tenants depending on how CloudTrail logs are ingested and normalized
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting

---

## Related AWS Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your AWS security tooling and licensing tier:

- Amazon GuardDuty — IAMUser/AnomalousBehavior
- Amazon GuardDuty — UnauthorizedAccess:IAMUser/TorIPCaller
