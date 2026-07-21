# Bulk Data Access and Smash and Grab Exfiltration — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/14
**MITRE ATT&CK:** T1530
**Reference:** https://attack.mitre.org/techniques/T1530/

---

## Query 1 — High Volume File Download Activity

This query surfaces accounts performing an unusually high volume of file downloads from SharePoint or OneDrive within a defined time window. Adjust the download threshold and time window based on your environment and what constitutes normal user activity.

```kql
let DownloadThreshold = 100;
let TimeWindow = 1h;
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "FileDownloaded",
    "FileSyncDownloadedFull",
    "FileAccessed"
)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| summarize
    DownloadCount = count(),
    FirstActivity = min(Timestamp),
    LastActivity = max(Timestamp),
    DistinctFiles = dcount(ObjectName),
    IPAddresses = make_set(ClientIP)
    by AccountUpn, bin(Timestamp, TimeWindow)
| where DownloadCount >= DownloadThreshold
| sort by DownloadCount desc
```

---

## Query 2 — External Sharing of Sensitive Content

Attackers frequently create anonymous or external sharing links to exfiltrate data without needing to download files directly. This query surfaces accounts creating external sharing links which may indicate data staging for exfiltration.

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "SharingInvitationCreated",
    "AnonymousLinkCreated",
    "AddedToSecureLink"
)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| extend EventDetails = parse_json(RawEventData)
| extend
    SharedWith = tostring(EventDetails.TargetUserOrGroupName),
    SharingType = tostring(EventDetails.EventData)
| project
    Timestamp,
    PerformedBy = AccountUpn,
    ObjectName,
    SharedWith,
    SharingType,
    ClientIP
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- Table availability varies by tenant configuration and licensing — run `search * | distinct $table` in Advanced Hunting to confirm which tables are available in your environment before executing these queries
- Requires the `CloudAppEvents` table which is available with Microsoft Defender for Cloud Apps licensing
- Organizations using Microsoft Sentinel should use the `OfficeActivity` table and adjust field names accordingly
- `DownloadThreshold` in Query 1 is set to 100 by default — this will need significant tuning based on your environment as normal download volumes vary widely across organizations
- `TimeWindow` is set to 1 hour — smash and grab attacks tend to move quickly so a tighter window may be more appropriate depending on your environment
- `ClientIP` is an already extracted field containing the IP address of the request
- `make_set(ClientIP)` in Query 1 collects all unique IP addresses observed across download events for the same user — useful for identifying multiple source IPs
- Query 2 does not include a threshold as any external sharing activity warrants review depending on your organization's data sharing policies
- Pay particular attention to bulk download or sharing activity from accounts that have recently exhibited other suspicious behavior such as MFA failures, unusual sign-ins, or privilege changes
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting

---

## Related Defender Detections

The following related detections may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Microsoft Defender for Cloud Apps — Unusual file download activity
- Microsoft Defender for Cloud Apps — Mass download by a single user
- Microsoft Defender for Cloud Apps — Suspicious data access following inactivity
- Entra ID Protection — Impossible travel
