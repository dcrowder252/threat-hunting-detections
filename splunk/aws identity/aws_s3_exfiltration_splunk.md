# S3 Data Enumeration and Exfiltration — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/28
**MITRE ATT&CK:** T1530
**Reference:** https://attack.mitre.org/techniques/T1530/

---

## Query 1 — S3 Bucket Enumeration

This query surfaces accounts performing S3 bucket enumeration activity. Listing buckets and reading bucket policies are common early-stage reconnaissance actions performed by attackers who have obtained AWS credentials.

```spl
index=<your_index> sourcetype="aws:cloudtrail"
(eventName="ListBuckets" OR
eventName="GetBucketPolicy" OR
eventName="GetBucketAcl" OR
eventName="GetBucketLocation")
errorCode=success
NOT userIdentity.type="AWSService"
| rex field=userIdentity.principalId ":(?P<AssumedRoleUser>[^:]+)$"
| eval PerformedBy=case(
    'userIdentity.type'="IAMUser", user,
    'userIdentity.type'="AssumedRole", AssumedRoleUser,
    true(), "Unknown")
| table _time, PerformedBy, userIdentity.type, eventName, sourceIPAddress, awsRegion, userAgent
| rename userIdentity.type as IdentityType, sourceIPAddress as IPAddress
| sort - _time
```

---

## Query 2 — High Volume S3 Object Downloads

This query surfaces accounts performing an unusually high volume of S3 object downloads within a defined time window. Adjust the download threshold based on your environment and what constitutes normal data access activity.

> Note: This query requires S3 data event logging to be enabled in AWS CloudTrail. Management events alone will not capture individual GetObject calls.

```spl
index=<your_index> sourcetype="aws:cloudtrail"
eventName="GetObject"
errorCode=success
NOT userIdentity.type="AWSService"
| rex field=userIdentity.principalId ":(?P<AssumedRoleUser>[^:]+)$"
| eval PerformedBy=case(
    'userIdentity.type'="IAMUser", user,
    'userIdentity.type'="AssumedRole", AssumedRoleUser,
    true(), "Unknown")
| spath path=requestParameters.bucketName output=BucketName
| bucket _time span=1h
| stats
    count as DownloadCount,
    min(_time) as FirstActivity,
    max(_time) as LastActivity,
    dc(BucketName) as DistinctBuckets
    by PerformedBy, sourceIPAddress, _time
| where DownloadCount >= 100
| eval FirstActivity=strftime(FirstActivity, "%Y-%m-%d %H:%M:%S")
| eval LastActivity=strftime(LastActivity, "%Y-%m-%d %H:%M:%S")
| table PerformedBy, DownloadCount, DistinctBuckets, FirstActivity, LastActivity, sourceIPAddress
| rename sourceIPAddress as IPAddress
| sort - DownloadCount
```

---

## Notes

- Adjust index value to match your environment
- Sourcetype for AWS CloudTrail logs in Splunk is typically `aws:cloudtrail` — adjust if your environment uses a different sourcetype
- `AWSService` is excluded from both queries as AWS services constantly call S3 APIs internally and generate significant noise
- `rex` extracts the username from `userIdentity.principalId` for AssumedRole events — the field is structured as `ROLEID:username` and the username is everything after the last colon
- `eval` with `case()` selects the correct username field based on identity type — `IAMUser` events store the username in `userIdentity.userName` which is also available as the flattened `user` field, while `AssumedRole` events use the extracted username from `principalId`
- Fields containing dot notation must be wrapped in single quotes inside `eval` expressions in Splunk
- Query 2 requires S3 data event logging to be enabled in AWS CloudTrail — individual `GetObject` calls are not captured by management event logging alone
- `DownloadCount` threshold in Query 2 is set to 100 by default — adjust based on your environment as normal download volumes vary widely across organizations
- `DistinctBuckets` shows how many unique S3 buckets were accessed — an attacker accessing many buckets in a short window is a strong indicator of broad data access
- `strftime` is used to convert epoch timestamps to human readable format
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting

---

## Related AWS Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your AWS security tooling and licensing tier:

- Amazon GuardDuty — Exfiltration:S3/AnomalousBehavior
- Amazon GuardDuty — Discovery:S3/AnomalousBehavior
- AWS Security Hub — S3 bucket security findings
