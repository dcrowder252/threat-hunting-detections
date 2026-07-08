# Known Campaign IP Indicators — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1071.001, T1048.001
**Reference:** https://attack.mitre.org/techniques/T1071/001/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```spl
index=* sourcetype=*
(
    dest_ip="192.121.22.94" OR
    dest_ip="109.205.195.211" OR
    dest_ip="188.40.187.145" OR
    dest_ip="171.22.183.43" OR
    dest_ip="194.127.178.21" OR
    dest_ip="172.96.137.160" OR
    dest_ip="193.242.184.150" OR
    dest_ip="185.174.100.203"
)
| table _time, ComputerName, User, src_ip, dest_ip, dest_port
| sort -_time
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

- Adjust index and sourcetype values to match your environment
- Replace `dest_ip`, `src_ip`, and `dest_port` with the correct field names in your environment
- IOC fidelity decays over time — these IPs may no longer be associated with malicious infrastructure depending on when this search is run
- Always validate IOCs against current threat intelligence before using for alerting
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
