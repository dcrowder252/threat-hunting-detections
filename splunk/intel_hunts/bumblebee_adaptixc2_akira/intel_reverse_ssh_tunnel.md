# Reverse SSH Tunnel Established via SSH.exe — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1572, T1021.001
**Reference:** https://attack.mitre.org/techniques/T1572/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\ssh.exe"
CommandLine="* -R *"
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- The `-R` flag indicates a reverse port forward — legitimate administrative use of this flag is rare on production systems
- Review the full command line for external IP addresses and port numbers to understand the tunnel destination
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
