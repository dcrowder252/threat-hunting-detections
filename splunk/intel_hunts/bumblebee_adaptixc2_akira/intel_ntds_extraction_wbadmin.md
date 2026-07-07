# NTDS.dit Extraction via wbadmin.exe — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1003.003
**Reference:** https://attack.mitre.org/techniques/T1003/003/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\wbadmin.exe"
(
    CommandLine="*ntds.dit*" OR
    CommandLine="*start backup*"
)
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- This activity is rarely legitimate outside of approved domain controller backup operations — any hit outside of a known maintenance window should be treated as high priority
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
