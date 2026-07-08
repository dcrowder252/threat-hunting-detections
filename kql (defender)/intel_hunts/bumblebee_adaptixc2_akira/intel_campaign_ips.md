# Known Campaign IP Indicators — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1071.001, T1048.001
**Reference:** https://attack.mitre.org/techniques/T1071/001/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```kql
DeviceNetworkEvents
| where RemoteIP in (
    "192.121.22.94",
    "109.205.195.211",
    "188.40.187.145",
    "171.22.183.43",
    "194.127.178.21",
    "172.96.137.160",
    "193.242.184.150",
    "185.174.100.203"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort
| sort by Timestamp desc
```

---

## IP Reference

- `192.121.22.94` — BumbleBee C2
- `109.205.195.211` — BumbleBee C2
- `188.40.187.145` — BumbleBee C2
- `171.22.183.43` — BumbleBee C2
- `194.127.178.21` — BumbleBee C2
- `172.96.137.160` — AdaptixC2
- `193.242.184.150` — Reverse SSH Tunnel
- `185.174.100.203` — Exfiltration Server

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- `InitiatingProcessFileName` identifies the process making the outbound connection — useful for triage context
- IOC fidelity decays over time — these IPs may no longer be associated with malicious infrastructure depending on when this search is run
- Always validate IOCs against current threat intelligence before using for alerting
- Field names may vary across tenants — adjust as necessary for your environment
