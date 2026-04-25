#event_simpleName="DnsRequest"
| DomainName=*anydesk.com or DomainName=*teamviewer.com or DomainName=*screenconnect.com or DomainName=*atera.com or DomainName=*splashtop.com or DomainName=*splashtop.eu

//Regex version

**#event_simpleName="DnsRequest"
| DomainName=/(anydesk\.com|teamviewer\.com|screenconnect\.com|atera\.com|splashtop\.com|splashtop\.eu)$/i**

NOTE: Add in other domain names for other RMM tools as you see fit.
