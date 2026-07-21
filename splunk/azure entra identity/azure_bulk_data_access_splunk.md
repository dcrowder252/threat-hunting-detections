# Bulk Data Access and Smash and Grab Exfiltration — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/17
**MITRE ATT&CK:** T1530
**Reference:** https://attack.mitre.org/techniques/T1530/

---

## Query 1 — High Volume File Download Activity

This query surfaces accounts performing an unusually high volume of file downloads from SharePoint or OneDrive within a defined time window. Adjust the download threshold and time window based on your environment and what constitutes normal user activity.

```spl
index=<your_index> sourcetype="o365:management:activity"
(Operation="FileDownloaded" OR
Operation="FileSyncDownloadedFull" OR
Operation="FileAccessed")
(Workload="SharePoint" OR Workload="OneDrive")
NOT UserId="app@sharepoint"
| bucket _time span=1h
| stats
    count as DownloadCount,
    min(_time) as FirstActivity,
    max(_time) as LastActivity,
    dc(ObjectId) as DistinctFiles
    by UserId, ClientIP, _time
| where DownloadCount >= 100
| table UserId, DownloadCount, DistinctFiles, FirstActivity, LastActivity, ClientIP
| rename UserId as User
| sort - DownloadCount
```

---

## Query 2 — External Sharing of Sensitive Content

Attackers frequently create anonymous or external sharing links to exfiltrate data without needing to download files directly. This query surfaces accounts creating external sharing links which may indicate data staging for exfiltration.

```spl
index=<your_index> sourcetype="o365:management:activity"
(Operation="SharingInvitationCreated" OR
Operation="AnonymousLinkCreated" OR
Operation="AddedToSecureLink")
(Workload="SharePoint" OR Workload="OneDrive")
| table _time, UserId, ObjectId, Operation, TargetUserOrGroupName, ClientIP
| rename UserId as PerformedBy, ObjectId as SharedItem, TargetUserOrGroupName as SharedWith
| sort - _time
```

---

## Notes

- Adjust index value to match your environment
- Sourcetype for SharePoint and OneDrive activity is typically `o365:management:activity` — adjust if your environment uses a different sourcetype
- `Operation` field values may vary depending on how your Microsoft 365 audit logs are normalized in Splunk — adjust as necessary to conform to your data set
- `UserId` contains the UPN of the account performing the download or sharing activity
- `DownloadThreshold` in Query 1 is set to 100 by default — this will need significant tuning based on your environment as normal download volumes vary widely across organizations
- `DistinctFiles` in Query 1 shows how many unique files were accessed versus the same file being downloaded repeatedly — useful for triage
- Query 2 does not include a threshold as any external sharing activity warrants review depending on your organization's data sharing policies
- Pay particular attention to bulk download or sharing activity from accounts that have recently exhibited other suspicious behavior such as MFA failures or unusual sign-ins
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting

---

## Related Defender Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Microsoft Defender for Cloud Apps — Unusual file download activity
- Microsoft Defender for Cloud Apps — Mass download by a single user
- Microsoft Defender for Cloud Apps — Suspicious data access following inactivity
- Entra ID Protection — Impossible travel
