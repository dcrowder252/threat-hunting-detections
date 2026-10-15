# CrowdStrike LogScale — Linux LOLBin Abuse: Netcat

## Query 1: Reverse Shell Execution Flags

Hunt for netcat invocations using flags associated with program execution after connection — the standard reverse shell mechanism.

```
#event_simpleName=ProcessRollup2
| event_platform=Lin
| ImageFileName=/\/(nc|ncat|netcat)$/i
| CommandLine=/(\s-e\s|\s--exec\s|\s-c\s|\s--sh-exec\s)/i
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName], sortby=@timestamp, order=desc, limit=10000)
```

---

## Query 2: External Network Connections

Hunt for netcat variants making outbound connections to external IP addresses. Filters out RFC 1918 private ranges and loopback.

```
#event_simpleName=NetworkConnectIP4
| event_platform=Lin
| ContextBaseFileName=/(nc|ncat|netcat)$/i
| RemoteAddressIP4 != /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
| table([@timestamp, ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort], sortby=@timestamp, order=desc, limit=10000)
```

---

## Query 3: Spawned by Unexpected Parent Processes

Hunt for netcat spawned by web server, database, or application processes that have no legitimate reason to invoke network utilities.

```
#event_simpleName=ProcessRollup2
| event_platform=Lin
| ImageFileName=/\/(nc|ncat|netcat)$/i
| ParentBaseFileName=/(apache2|nginx|httpd|tomcat|java|mysqld|mysqld_safe|postgres|mongod|php-fpm|php|ruby|node)/i
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName], sortby=@timestamp, order=desc, limit=10000)
```

---

## Notes

- All queries scoped to Linux endpoints using `| event_platform=Lin`
- CrowdStrike LogScale returns a maximum of 200 results by default. Each query below uses `limit=10000` in the table command. Adjust time window or add additional filters if results are still being capped.
- `ContextBaseFileName` is used in NetworkConnectIP4 events — `ImageFileName` is not available in those events
- Queries match `nc`, `ncat`, and `netcat` to cover all common variant names
- RFC 1918 private address ranges (10.x, 172.16-31.x, 192.168.x) and loopback (127.x) are excluded from IP-based queries to reduce noise from legitimate internal use
- The `-e` and `--exec` flags (Query 1) execute a specified program after a connection is established — the classic reverse shell pattern. OpenBSD netcat (common on Debian/Ubuntu) ships without these flags; in those environments attackers may use named pipes via `mkfifo` instead.
- Ncat supports SSL encryption (`--ssl`), which encrypts the reverse shell channel — Query 2 catches the connection at the network layer regardless of encryption
- A web server or database spawning netcat (Query 3) is a high-confidence indicator of post-exploitation activity — correlate with web server access logs to identify the triggering request
