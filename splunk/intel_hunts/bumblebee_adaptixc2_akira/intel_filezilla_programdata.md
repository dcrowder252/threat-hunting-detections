# FileZilla Installer Executed from ProgramData — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1048.001, T1219
**Reference:** https://attack.mitre.org/techniques/T1048/001/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\ProgramData\*"
Image="*FileZilla*"
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## IOC Search — Known Exfiltration Server

```spl
index=* sourcetype=*
dest_ip="185.174.100.203" OR dest="185.174.100.203"
| table _time, ComputerName, User, src_ip, dest_ip, dest_port
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- The IOC search targets the exfiltration server observed in this campaign — treat as time sensitive given IOC decay
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
