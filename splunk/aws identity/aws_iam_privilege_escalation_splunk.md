# IAM Privilege Escalation via Policy Changes — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/28
**MITRE ATT&CK:** T1548.005
**Reference:** https://attack.mitre.org/techniques/T1548/005/

---

## Query

```spl
index=<your_index> sourcetype="aws:cloudtrail"
(eventName="PutUserPolicy" OR
eventName="AttachUserPolicy" OR
eventName="PutRolePolicy" OR
eventName="AttachRolePolicy" OR
eventName="CreatePolicy" OR
eventName="PutGroupPolicy" OR
eventName="AttachGroupPolicy")
errorCode=success
| rex field=userIdentity.principalId ":(?P<AssumedRoleUser>[^:]+)$"
| eval PerformedBy=case(
    'userIdentity.type'="IAMUser", user,
    'userIdentity.type'="AssumedRole", AssumedRoleUser,
    true(), "Unknown")
| table _time, PerformedBy, userIdentity.type, eventName, requestParameters.userName, requestParameters.roleName, requestParameters.policyArn, requestParameters.policyName, sourceIPAddress, awsRegion
| rename userIdentity.type as IdentityType, requestParameters.userName as TargetUser, requestParameters.roleName as TargetRole, requestParameters.policyArn as PolicyArn, requestParameters.policyName as PolicyName, sourceIPAddress as IPAddress
| sort - _time
```

---

## Notes

- Adjust index value to match your environment
- Sourcetype for AWS CloudTrail logs in Splunk is typically `aws:cloudtrail` — adjust if your environment uses a different sourcetype
- `errorCode=success` filters to successful policy changes only — remove to include failed attempts — running a separate search for high volumes of failed policy modification attempts may also be worth investigating as it could indicate an attacker probing for privilege escalation opportunities
- `rex` extracts the username from `userIdentity.principalId` for AssumedRole events — the field is structured as `ROLEID:username` and the username is everything after the last colon
- `eval` with `case()` selects the correct username field based on identity type — `IAMUser` events store the username in `userIdentity.userName` which is also available as the flattened `user` field, while `AssumedRole` events use the extracted username from `principalId`
- Fields containing dot notation must be wrapped in single quotes inside `eval` expressions in Splunk
- `IdentityType` is included in the output to help distinguish between human IAM users and assumed role sessions during triage
- `TargetUser`, `TargetRole`, and `TargetGroup` will be populated depending on the type of operation — only the relevant field will contain a value for each event
- `PolicyArn` will be populated for attach operations — `PolicyName` will be populated for put and create operations
- Pay particular attention to events referencing `AdministratorAccess` or wildcard policies outside of approved change management windows
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting

---

## Related AWS Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your AWS security tooling and licensing tier:

- Amazon GuardDuty — PrivilegeEscalation:IAMUser/AdministrativePermissions
- AWS Security Hub — IAM policy modification findings
