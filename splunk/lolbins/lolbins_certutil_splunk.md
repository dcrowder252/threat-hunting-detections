# Certutil.exe Abuse — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/08/30
**MITRE ATT&CK:** T1105, T1140
**Reference:** https://attack.mitre.org/techniques/T1105/

---

## Query 1 — Certutil Download Cradle

This query detects certutil invocations containing flags associated with downloading files from remote locations. Legitimate certutil usage rarely includes these flags outside of specific PKI management scenarios.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\certutil.exe"
(CommandLine="*-urlcache*" OR CommandLine="*-split*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 2 — Certutil Encode and Decode Activity

This query detects certutil invocations used to encode or decode file content — a common technique for obfuscating payloads delivered through other means.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\certutil.exe"
(CommandLine="*-decode*" OR CommandLine="*-encode*" OR CommandLine="*-decodehex*")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Query 3 — Certutil Spawned by Suspicious Parent Process

This query detects certutil spawned by parent processes commonly associated with phishing-based initial access including Office applications and scripting engines.

```spl
index=* sourcetype=*
EventCode=4688 OR EventCode=1
Image="*\certutil.exe"
(ParentImage="*\winword.exe" OR
ParentImage="*\excel.exe" OR
ParentImage="*\powerpnt.exe" OR
ParentImage="*\outlook.exe" OR
ParentImage="*\mshta.exe" OR
ParentImage="*\wscript.exe" OR
ParentImage="*\cscript.exe" OR
ParentImage="*\explorer.exe")
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort - _time
```

---

## Notes

- Adjust index and sourcetype values to match your environment
- EventCode 4688 requires command line auditing to be enabled
- EventCode 1 is Sysmon process creation (recommended for better coverage)
- All three queries can be combined using OR logic if a single broad search is preferred — separating them allows for more granular tuning per technique
- `explorer.exe` is included as a parent process in Query 3 but may generate more noise than the other parent processes listed — can be removed if volume is too high in your environment
- Field names may vary depending on your Splunk configuration and data inputs — adjust as necessary to conform to your data set
- Review results against known administrative baselines before alerting
