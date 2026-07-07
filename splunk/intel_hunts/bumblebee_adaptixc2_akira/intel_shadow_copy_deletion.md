# Shadow Copy Deletion via WMI and PowerShell — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1490, T1070
**Reference:** https://attack.mitre.org/techniques/T1490/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
(Image="*\powershell.exe" OR Image="*\pwsh.exe")
CommandLine="*Win32_Shadowcopy*"
CommandLine="*Remove-WmiObject*"
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- This combination of Win32_Shadowcopy and Remove-WmiObject is a strong ransomware precursor indicator and should be treated as a critical alert
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
