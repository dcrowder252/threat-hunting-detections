# Splunk — Linux LOLBin Abuse: Python

## Query 1: Inline Code Execution via -c Flag

Hunt for python and python3 invocations using the `-c` flag to execute inline code. Covers common reverse shell and payload execution patterns including base64-encoded payloads.

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(Image="*/python" OR Image="*/python2" OR Image="*/python3")
(CommandLine="* -c import*" OR CommandLine="* -c exec*" OR CommandLine="* -c eval*"
 OR CommandLine="* -c __import__*" OR CommandLine="* -c 'import*" OR CommandLine="* -c \"import*"
 OR CommandLine="* -c 'exec*" OR CommandLine="* -c \"exec*")
| table _time, host, user, Image, CommandLine, ParentCommandLine
| sort - _time
```

---

## Query 2: Reverse Shell Module References

Hunt for python and python3 command lines referencing modules and functions commonly used in reverse shell one-liners.

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(Image="*/python" OR Image="*/python2" OR Image="*/python3")
(CommandLine="*socket*" OR CommandLine="*os.dup2*" OR CommandLine="*pty.spawn*"
 OR CommandLine="*subprocess.call*" OR CommandLine="*subprocess.Popen*")
| table _time, host, user, Image, CommandLine, ParentCommandLine
| sort - _time
```

---

## Query 3: Spawned by Unexpected Parent Processes

Hunt for python spawned by web server, database, or application processes that have no legitimate reason to invoke an interpreter inline.

```spl
index=linux sourcetype="linux_audit" OR sourcetype="syslog"
(Image="*/python" OR Image="*/python2" OR Image="*/python3")
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
- Queries match `python`, `python2`, and `python3` to cover all common interpreter names
- The `-c` flag combined with `import`, `exec`, or `eval` (Query 1) is the canonical pattern for Python-based reverse shells and payload execution. Base64-encoded payloads frequently use `__import__('base64').b64decode(...)` — the `__import__` match catches those.
- The combination of `socket` with `os.dup2` or `subprocess` in a Python command line (Query 2) is the signature of the most common Python reverse shell pattern. `pty.spawn` is used to upgrade a basic shell to a fully interactive TTY.
- Python spawned directly by apache2, nginx, or a database process (Query 3) with no corresponding application framework relationship is a strong indicator of exploitation activity
