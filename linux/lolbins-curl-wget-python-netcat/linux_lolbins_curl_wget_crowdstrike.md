# CrowdStrike LogScale — Linux LOLBin Abuse: Curl and Wget

## Query 1: External Network Connections

Hunt for curl and wget making outbound connections to external IP addresses. Filters out RFC 1918 private ranges and loopback to focus on traffic leaving the network.

```
#event_simpleName=NetworkConnectIP4
| event_platform=Lin
| ContextBaseFileName=/(curl|wget)$/i
| RemoteAddressIP4 != /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
| table([@timestamp, ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort], sortby=@timestamp, order=desc, limit=10000)
```

---

## Query 2: Suspicious Download Targets and Pipe-to-Shell Patterns

Hunt for curl and wget command lines referencing suspicious output destinations or patterns consistent with pipe-to-shell execution. Covers downloads to memory-backed and world-writable paths.

```
#event_simpleName=ProcessRollup2
| event_platform=Lin
| ImageFileName=/(curl|wget)$/i
| CommandLine=/(\/tmp\/|\/dev\/shm\/|\/var\/tmp\/|\|.*(bash|sh\b|python[23]?|perl))/i
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName], sortby=@timestamp, order=desc, limit=10000)
```

---

## Query 3: Spawned by Unexpected Parent Processes

Hunt for curl and wget spawned by web server, database, or application processes that have no legitimate reason to initiate outbound downloads.

```
#event_simpleName=ProcessRollup2
| event_platform=Lin
| ImageFileName=/(curl|wget)$/i
| ParentBaseFileName=/(apache2|nginx|httpd|tomcat|java|mysqld|mysqld_safe|postgres|mongod|php-fpm|php|ruby|node)/i
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName], sortby=@timestamp, order=desc, limit=10000)
```

---

## Notes

- All queries scoped to Linux endpoints using `| event_platform=Lin`
- CrowdStrike LogScale returns a maximum of 200 results by default. Each query below uses `limit=10000` in the table command. Adjust time window or add additional filters if results are still being capped.
- `ContextBaseFileName` is used in NetworkConnectIP4 events — `ImageFileName` is not available in those events
- RFC 1918 private address ranges (10.x, 172.16-31.x, 192.168.x) and loopback (127.x) are excluded from IP-based queries to reduce noise from legitimate internal tooling and monitoring agents
- Query 1 may return hits for APIPA addresses (169.254.x.x) — these are link-local addresses assigned when DHCP fails and are not routable external IPs. Add `| RemoteAddressIP4 != /^169\.254\./` to exclude them if they generate noise in your environment.
- `/dev/shm/` is a memory-backed tmpfs filesystem — files written there do not persist to disk across reboots and are commonly used by attackers to avoid leaving artifacts on disk
- The pipe pattern (`| bash`, `| sh`, `| python`) in Query 2 surfaces fileless execution where downloaded content is piped directly to an interpreter with no file ever written to disk
- Query 2 may produce significant volume on `/tmp/` matches in environments where legitimate tooling frequently writes to that directory. If noise is too high, remove the `/tmp/` condition and focus on `/dev/shm/`, `/var/tmp/`, and the pipe-to-shell patterns, which are higher fidelity.
- Web server or application processes spawning curl or wget (Query 3) is a strong indicator of web shell activity or exploitation — correlate with web server access logs to identify the triggering request
