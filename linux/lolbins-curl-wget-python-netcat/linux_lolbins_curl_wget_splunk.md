# Splunk — Linux LOLBin Abuse: Curl and Wget

## Query 1: External Network Connections

Hunt for curl and wget making outbound connections to external IP addresses. Filters out RFC 1918 private ranges and loopback to focus on traffic leaving the network.

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(Image="*/curl" OR Image="*/wget")
| where NOT cidrmatch("10.0.0.0/8", dest_ip)
    AND NOT cidrmatch("172.16.0.0/12", dest_ip)
    AND NOT cidrmatch("192.168.0.0/16", dest_ip)
    AND NOT cidrmatch("127.0.0.0/8", dest_ip)
| table _time, host, user, Image, dest_ip, dest_port
| sort - _time
```

---

## Query 2: Suspicious Download Targets and Pipe-to-Shell Patterns

Hunt for curl and wget command lines referencing suspicious output destinations or patterns consistent with pipe-to-shell execution. Covers downloads to memory-backed and world-writable paths.

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(Image="*/curl" OR Image="*/wget")
(CommandLine="*/tmp/*" OR CommandLine="*/dev/shm/*" OR CommandLine="*/var/tmp/*"
 OR CommandLine="*| bash*" OR CommandLine="*| sh *" OR CommandLine="*|bash*" OR CommandLine="*|sh *"
 OR CommandLine="*| python*" OR CommandLine="*| python3*" OR CommandLine="*| perl*")
| table _time, host, user, Image, CommandLine, ParentCommandLine
| sort - _time
```

---

## Query 3: Spawned by Unexpected Parent Processes

Hunt for curl and wget spawned by web server, database, or application processes that have no legitimate reason to initiate outbound downloads.

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(Image="*/curl" OR Image="*/wget")
(ParentImage="*/apache2" OR ParentImage="*/nginx" OR ParentImage="*/httpd"
 OR ParentImage="*/tomcat" OR ParentImage="*/java" OR ParentImage="*/mysqld"
 OR ParentImage="*/mysqld_safe" OR ParentImage="*/postgres" OR ParentImage="*/mongod"
 OR ParentImage="*/php-fpm" OR ParentImage="*/php" OR ParentImage="*/ruby"
 OR ParentImage="*/node")
| table _time, host, user, Image, CommandLine, ParentImage
| sort - _time
```

---

## Notes

- Adjust `index` and `sourcetype` values to match your environment. Common Linux log sourcetypes include `linux_audit`, `syslog`, `linux_secure`, and `auditd` — adjust based on your Splunk configuration.
- Auditd is recommended as the primary data source for Linux process execution telemetry as it provides richer command-line visibility than syslog alone
- RFC 1918 private address ranges and loopback are excluded in Query 1 using `cidrmatch()` to reduce noise from legitimate internal tooling and monitoring agents
- Query 1 may return hits for APIPA addresses (169.254.x.x) — these are link-local addresses assigned when DHCP fails and are not routable external IPs. Add `| where NOT cidrmatch("169.254.0.0/16", dest_ip)` to exclude them if they generate noise in your environment.
- `/dev/shm/` is a memory-backed tmpfs filesystem — files written there do not persist to disk across reboots and are commonly used by attackers to avoid leaving artifacts on disk
- The pipe pattern (`| bash`, `| sh`, `| python`) in Query 2 surfaces fileless execution where downloaded content is piped directly to an interpreter with no file ever written to disk
- Query 2 may produce significant volume on `/tmp/` matches in environments where legitimate tooling frequently writes to that directory. If noise is too high, remove the `/tmp/` condition and focus on `/dev/shm/`, `/var/tmp/`, and the pipe-to-shell patterns, which are higher fidelity.
- Web server or application processes spawning curl or wget (Query 3) is a strong indicator of web shell activity or exploitation — correlate with web server access logs to identify the triggering request
