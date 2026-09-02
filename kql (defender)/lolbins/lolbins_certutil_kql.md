# Certutil.exe Abuse — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/08/30
**MITRE ATT&CK:** T1105, T1140
**Reference:** https://attack.mitre.org/techniques/T1105/

---

## Query 1 — Certutil Download Cradle

This query detects certutil invocations containing flags associated with downloading files from remote locations. Legitimate certutil usage rarely includes these flags outside of specific PKI management scenarios.

```kql
DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache", "-split")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 2 — Certutil Encode and Decode Activity

This query detects certutil invocations used to encode or decode file content — a common technique for obfuscating payloads delivered through other means.

```kql
DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-decode", "-encode", "-decodehex")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 3 — Certutil Spawned by Suspicious Parent Process

This query detects certutil spawned by parent processes commonly associated with phishing-based initial access including Office applications and scripting engines.

```kql
DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "explorer.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- This query is written for Microsoft Defender Advanced Hunting (KQL)
- All three queries can be combined using OR logic if a single broad search is preferred — separating them allows for more granular tuning per technique
- `explorer.exe` is included as a parent process in Query 3 but may generate more noise than the other parent processes listed — can be removed if volume is too high in your environment
- `InitiatingProcessFileName` surfaces the parent process for additional triage context
- Field names may vary across tenants — adjust as necessary for your environment
- Review results against known administrative baselines before alerting
