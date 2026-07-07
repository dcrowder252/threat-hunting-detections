# BumbleBee DGA Domain Indicators — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1568.002
**Reference:** https://attack.mitre.org/techniques/T1568/002/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```spl
index=* sourcetype=*
(
    QueryName="ev2sirbd269o5j.org" OR
    QueryName="2rxyt9urhq0bgj.org" OR
    QueryName="d1hmxkpwby0d4s.org" OR
    QueryName="yj6jurm5qqkye5.org" OR
    QueryName="ewujsfb1dp5ran.org" OR
    QueryName="8doj8uvx604eck.org" OR
    QueryName="kwywztxoo2xdot.org" OR
    QueryName="ky1d1p1daahe5t.org" OR
    QueryName="ovh1kn1tcqw5kp.org" OR
    QueryName="6cimu4mc085em8.org" OR
    QueryName="5ka8rxp6t6eup2.org" OR
    QueryName="ks501oz9nm3v05.org" OR
    QueryName="v5rjsdqogstopr.org"
)
| table _time, ComputerName, User, QueryName
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- Replace `QueryName` with the correct DNS query field name in your environment
- These domains are associated with BumbleBee Wave 2 DGA infrastructure observed in this campaign
- IOC fidelity decays over time — these domains may no longer be active or associated with malicious infrastructure depending on when this search is run
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
