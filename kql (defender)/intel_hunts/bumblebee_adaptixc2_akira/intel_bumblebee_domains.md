# BumbleBee DGA Domain Indicators — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1568.002
**Reference:** https://attack.mitre.org/techniques/T1568/002/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```kql
DeviceNetworkEvents
| where RemoteUrl has_any (
    "ev2sirbd269o5j.org",
    "2rxyt9urhq0bgj.org",
    "d1hmxkpwby0d4s.org",
    "yj6jurm5qqkye5.org",
    "ewujsfb1dp5ran.org",
    "8doj8uvx604eck.org",
    "kwywztxoo2xdot.org",
    "ky1d1p1daahe5t.org",
    "ovh1kn1tcqw5kp.org",
    "6cimu4mc085em8.org",
    "5ka8rxp6t6eup2.org",
    "ks501oz9nm3v05.org",
    "v5rjsdqogstopr.org"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- These domains are associated with BumbleBee Wave 2 DGA infrastructure observed in this campaign
- IOC fidelity decays over time — these domains may no longer be active or associated with malicious infrastructure depending on when this search is run
- Always validate IOCs against current threat intelligence before using for alerting
- Field names may vary across tenants — adjust as necessary for your environment
