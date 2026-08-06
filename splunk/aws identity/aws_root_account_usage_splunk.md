# Root Account Usage — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/28
**MITRE ATT&CK:** T1078.004
**Reference:** https://attack.mitre.org/techniques/T1078/004/

---

## Query

```spl
index=<your_index> sourcetype="aws:cloudtrail"
userIdentity.type="Root"
| table _time, eventName, sourceIPAddress, awsRegion, userAgent, errorCode
| rename sourceIPAddress as IPAddress
| sort - _time
```

---

## Notes

- Adjust index value to match your environment
- Sourcetype for AWS CloudTrail logs in Splunk is typically `aws:cloudtrail` — adjust if your environment uses a different sourcetype
- `userIdentity.type="Root"` is the reliable indicator of root account usage — the username field may not display "root" and could show the account alias, account ID, or be empty — `userIdentity.type` should be treated as the definitive filter for this detection
- All root account activity should be treated as high priority — in well managed environments root usage is rare enough that every event warrants investigation regardless of what action was performed
- `errorCode` is included to surface failed attempts — even failed root account activity is worth investigating
- `userAgent` can provide additional context on how the root account was accessed — console vs API vs CLI
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting

---

## Related AWS Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your AWS security tooling and licensing tier:

- AWS Security Hub — Root account usage findings
- Amazon GuardDuty — Policy:IAMUser/RootCredentialUsage
