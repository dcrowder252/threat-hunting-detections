# RMM Domain Communication — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/04/21
**MITRE ATT&CK:** T1219.002
**Reference:** https://attack.mitre.org/techniques/T1219/002/

---

## Query

```spl
index=<your_index> sourcetype=<your_sourcetype>
(
    QueryName="*.anydesk.com" OR
    QueryName="*.teamviewer.com" OR
    QueryName="*.screenconnect.com" OR
    QueryName="*.atera.com" OR
    QueryName="*.splashtop.com" OR
    QueryName="*.splashtop.eu"
)
| table _time, ComputerName, User, QueryName
| sort -_time
```

---

## Notes

- Replace index and sourcetype values to match your environment
- Replace QueryName with the correct DNS query field name in your environment
- This list is not exhaustive — add additional RMM-related domains as needed
- Review results against your approved RMM tool baseline before alerting
