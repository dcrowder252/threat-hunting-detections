# Windows Binary Executing From Non-Standard Path — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/07/06
**MITRE ATT&CK:** T1574.001
**Reference:** https://attack.mitre.org/techniques/T1574/001/
**Intel Source:** https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

---

## Query — consent.exe Executing from Non-Standard Path

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\consent.exe"
NOT (Image="*\Windows\System32\consent.exe" OR Image="*\Windows\WinSxS\*\consent.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## Query — wab.exe Executing from Non-Standard Path

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\wab.exe"
NOT (Image="*\Program Files\Windows Mail\wab.exe" OR Image="*\Windows\WinSxS\*\wab.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- WinSxS is excluded in both queries as Windows stores side-by-side component copies there and generates significant false positive noise
- wab.exe is a Windows Address Book binary — its legitimate execution path is Program Files\Windows Mail not System32, so System32 is not used as an exclusion here
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
