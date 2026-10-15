# Linux LOLBin Abuse: Python — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/10/11
**MITRE ATT&CK:** T1059.006, T1071.001
**Reference:** https://attack.mitre.org/techniques/T1059/006/

---

## Query 1: Inline Code Execution via -c Flag

Hunt for python and python3 invocations using the `-c` flag to execute inline code. Covers common reverse shell and payload execution patterns including base64-encoded payloads.

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where FileName in ("python", "python2", "python3")
| where ProcessCommandLine has_any (
    " -c import", " -c exec", " -c eval", " -c __import__",
    " -c 'import", " -c \"import", " -c 'exec", " -c \"exec"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 2: Reverse Shell Module References

Hunt for python and python3 command lines referencing modules and functions commonly used in reverse shell one-liners.

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where FileName in ("python", "python2", "python3")
| where ProcessCommandLine has_any (
    "socket", "os.dup2", "pty.spawn",
    "subprocess.call", "subprocess.Popen"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 3: Spawned by Unexpected Parent Processes

Hunt for python spawned by web server, database, or application processes that have no legitimate reason to invoke an interpreter inline.

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where FileName in ("python", "python2", "python3")
| where InitiatingProcessFileName in (
    "apache2", "nginx", "httpd", "tomcat", "java",
    "mysqld", "mysqld_safe", "postgres", "mongod",
    "php-fpm", "php", "ruby", "node"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Notes

- These queries are written for Microsoft Defender Advanced Hunting (KQL)
- The `DeviceInfo` subquery filters results to Linux endpoints only — requires Microsoft Defender for Endpoint to be deployed on Linux endpoints
- Queries match `python`, `python2`, and `python3` to cover all common interpreter names
- The `-c` flag combined with `import`, `exec`, or `eval` (Query 1) is the canonical pattern for Python-based reverse shells and payload execution. Base64-encoded payloads frequently use `__import__('base64').b64decode(...)` — the `__import__` match catches those.
- The combination of `socket` with `os.dup2` or `subprocess` in a Python command line (Query 2) is the signature of the most common Python reverse shell pattern. `pty.spawn` is used to upgrade a basic shell to a fully interactive TTY.
- Python spawned directly by apache2, nginx, or a database process (Query 3) with no corresponding application framework relationship is a strong indicator of exploitation activity
- Field names may vary across tenants — adjust as necessary for your environment
