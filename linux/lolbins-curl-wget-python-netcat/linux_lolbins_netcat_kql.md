# Linux LOLBin Abuse: Netcat — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/10/11
**MITRE ATT&CK:** T1059.004, T1071.001, T1048.003
**Reference:** https://attack.mitre.org/techniques/T1059/004/

---

## Query 1: Reverse Shell Execution Flags

Hunt for netcat invocations using flags associated with program execution after connection — the standard reverse shell mechanism.

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where FileName in ("nc", "ncat", "netcat")
| where ProcessCommandLine has_any (
    " -e ", " --exec ", " --sh-exec ",
    " -c /bin/", " -c '/bin/", " -c \"/bin/"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 2: External Network Connections

Hunt for netcat variants making outbound connections to external IP addresses. Filters out RFC 1918 private ranges and loopback.

```kql
DeviceNetworkEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where InitiatingProcessFileName in ("nc", "ncat", "netcat")
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| sort by Timestamp desc
```

---

## Query 3: Spawned by Unexpected Parent Processes

Hunt for netcat spawned by web server, database, or application processes that have no legitimate reason to invoke network utilities.

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where FileName in ("nc", "ncat", "netcat")
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
- Queries match `nc`, `ncat`, and `netcat` to cover all common variant names
- Query 2 uses the built-in `ipv4_is_private()` function to exclude RFC 1918 ranges and loopback in a single clean filter
- The `-e` and `--exec` flags (Query 1) execute a specified program after a connection is established — the classic reverse shell pattern. OpenBSD netcat (common on Debian/Ubuntu) ships without these flags; in those environments attackers may use named pipes via `mkfifo` instead.
- Ncat supports SSL encryption (`--ssl`), which encrypts the reverse shell channel — Query 2 catches the connection at the network layer regardless of encryption
- A web server or database spawning netcat (Query 3) is a high-confidence indicator of post-exploitation activity — correlate with web server access logs to identify the triggering request
- Field names may vary across tenants — adjust as necessary for your environment
