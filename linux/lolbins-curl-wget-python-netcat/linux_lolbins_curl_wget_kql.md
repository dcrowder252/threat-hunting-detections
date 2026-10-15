# Linux LOLBin Abuse: Curl and Wget — Microsoft Defender (KQL)

**Author:** dcrowder252
**Date:** 2026/10/11
**MITRE ATT&CK:** T1105, T1059.004, T1071.001
**Reference:** https://attack.mitre.org/techniques/T1105/

---

## Query 1: External Network Connections

Hunt for curl and wget making outbound connections to external IP addresses. Filters out RFC 1918 private ranges and loopback to focus on traffic leaving the network.

```kql
DeviceNetworkEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where InitiatingProcessFileName in ("curl", "wget")
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp desc
```

---

## Query 2: Suspicious Download Targets and Pipe-to-Shell Patterns

Hunt for curl and wget command lines referencing suspicious output destinations or patterns consistent with pipe-to-shell execution. Covers downloads to memory-backed and world-writable paths.

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where FileName in ("curl", "wget")
| where ProcessCommandLine has_any (
    "/tmp/", "/dev/shm/", "/var/tmp/",
    "| bash", "|bash", "| sh ", "|sh ",
    "| python", "| python3", "| perl"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

---

## Query 3: Spawned by Unexpected Parent Processes

Hunt for curl and wget spawned by web server, database, or application processes that have no legitimate reason to initiate outbound downloads.

```kql
DeviceProcessEvents
| where DeviceId in (
    (DeviceInfo | where OSPlatform == "Linux" | distinct DeviceId)
)
| where FileName in ("curl", "wget")
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
- Query 1 uses the built-in `ipv4_is_private()` function to exclude RFC 1918 ranges and loopback in a single clean filter
- Query 1 may return hits for APIPA addresses (169.254.x.x) — these are link-local addresses assigned when DHCP fails and are not routable external IPs. Add `| where not(ipv4_is_in_range(RemoteIP, "169.254.0.0/16"))` to exclude them if they generate noise in your environment.
- `/dev/shm/` is a memory-backed tmpfs filesystem — files written there do not persist to disk across reboots and are commonly used by attackers to avoid leaving artifacts on disk
- The pipe pattern (`| bash`, `| sh`, `| python`) in Query 2 surfaces fileless execution where downloaded content is piped directly to an interpreter with no file ever written to disk
- Query 2 may produce significant volume on `/tmp/` matches in environments where legitimate tooling frequently writes to that directory. If noise is too high, remove the `/tmp/` condition and focus on `/dev/shm/`, `/var/tmp/`, and the pipe-to-shell patterns, which are higher fidelity.
- Web server or application processes spawning curl or wget (Query 3) is a strong indicator of web shell activity or exploitation — correlate with web server access logs to identify the triggering request
- Field names may vary across tenants — adjust as necessary for your environment
