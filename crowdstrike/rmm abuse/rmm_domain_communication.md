# RMM Domain Communication — CrowdStrike Falcon (LogScale)

**Author:** dcrowder252
**Date:** 2026/04/21
**MITRE ATT&CK:** T1219.002
**Reference:** https://attack.mitre.org/techniques/T1219/002/

---

## Query

```kusto
#event_simpleName="DnsRequest"
| DomainName=*anydesk.com or DomainName=*teamviewer.com or DomainName=*screenconnect.com or DomainName=*atera.com or DomainName=*splashtop.com or DomainName=*splashtop.eu
| table(_time, ComputerName, UserName, DomainName, RemoteAddressIP4)
| sort(field=_time, order=desc)
```

---

## Regex Version

```kusto
#event_simpleName="DnsRequest"
| DomainName=/(anydesk\.com|teamviewer\.com|screenconnect\.com|atera\.com|splashtop\.com|splashtop\.eu)$/i
| table(_time, ComputerName, UserName, DomainName, RemoteAddressIP4)
| sort(field=_time, order=desc)
```

---

## Notes

- This query is written for CrowdStrike Falcon LogScale (formerly Humio)
- This list is not exhaustive — add additional RMM-related domains as needed
- The regex version is recommended for cleaner, more maintainable queries as the domain list grows
- Review results against your approved RMM tool baseline before alerting
