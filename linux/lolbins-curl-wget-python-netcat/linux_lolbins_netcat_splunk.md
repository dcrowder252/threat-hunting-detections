# Splunk — Linux LOLBin Abuse: Netcat

## Query 1: Reverse Shell Execution Flags

Hunt for netcat invocations using flags associated with program execution after connection — the standard reverse shell mechanism.

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(Image="*/nc" OR Image="*/ncat" OR Image="*/netcat")
(CommandLine="* -e *" OR CommandLine="* --exec *" OR CommandLine="* --sh-exec *"
 OR CommandLine="* -c /bin/*" OR CommandLine="* -c '/bin/*" OR CommandLine="* -c \"/bin/*")
| table _time, host, user, Image, CommandLine, ParentCommandLine
| sort - _time
```

---

## Query 2: External Network Connections

Hunt for netcat variants making outbound connections to external IP addresses. Filters out RFC 1918 private ranges and loopback.

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(Image="*/nc" OR Image="*/ncat" OR Image="*/netcat")
| where NOT cidrmatch("10.0.0.0/8", dest_ip)
    AND NOT cidrmatch("172.16.0.0/12", dest_ip)
    AND NOT cidrmatch("192.168.0.0/16", dest_ip)
    AND NOT cidrmatch("127.0.0.0/8", dest_ip)
| table _time, host, user, Image, dest_ip, dest_port
| sort - _time
```

---

## Query 3: Spawned by Unexpected Parent Processes

Hunt for netcat spawned by web server, database, or application processes that have no legitimate reason to invoke network utilities.

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(Image="*/nc" OR Image="*/ncat" OR Image="*/netcat")
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
- Queries match `nc`, `ncat`, and `netcat` to cover all common variant names
- RFC 1918 private address ranges and loopback are excluded in Query 2 using `cidrmatch()` to reduce noise from legitimate internal use
- The `-e` and `--exec` flags (Query 1) execute a specified program after a connection is established — the classic reverse shell pattern. OpenBSD netcat (common on Debian/Ubuntu) ships without these flags; in those environments attackers may use named pipes via `mkfifo` instead.
- Ncat supports SSL encryption (`--ssl`), which encrypts the reverse shell channel — Query 2 catches the connection at the network layer regardless of encryption
- A web server or database spawning netcat (Query 3) is a high-confidence indicator of post-exploitation activity — correlate with web server access logs to identify the triggering request
