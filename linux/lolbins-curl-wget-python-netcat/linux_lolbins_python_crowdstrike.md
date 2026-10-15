# CrowdStrike LogScale — Linux LOLBin Abuse: Python

## Query 1: Inline Code Execution via -c Flag

Hunt for python and python3 invocations using the `-c` flag to execute inline code. Covers common reverse shell and payload execution patterns including base64-encoded payloads.

```
#event_simpleName=ProcessRollup2
| event_platform=Lin
| ImageFileName=/\/python[23]?$/i
| CommandLine=/-c\s+["\']?(import|exec|eval|__import__)/i
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName], sortby=@timestamp, order=desc, limit=10000)
```

---

## Query 2: Reverse Shell Module References

Hunt for python and python3 command lines referencing modules and functions commonly used in reverse shell one-liners.

```
#event_simpleName=ProcessRollup2
| event_platform=Lin
| ImageFileName=/\/python[23]?$/i
| CommandLine=/(socket|os\.dup2|pty\.spawn|subprocess\.call|subprocess\.Popen)/i
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName], sortby=@timestamp, order=desc, limit=10000)
```

---

## Query 3: Spawned by Unexpected Parent Processes

Hunt for python spawned by web server, database, or application processes that have no legitimate reason to invoke an interpreter inline.

```
#event_simpleName=ProcessRollup2
| event_platform=Lin
| ImageFileName=/\/python[23]?$/i
| ParentBaseFileName=/(apache2|nginx|httpd|tomcat|java|mysqld|mysqld_safe|postgres|mongod|php-fpm|php|ruby|node)/i
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName], sortby=@timestamp, order=desc, limit=10000)
```

---

## Notes

- All queries scoped to Linux endpoints using `| event_platform=Lin`
- CrowdStrike LogScale returns a maximum of 200 results by default. Each query below uses `limit=10000` in the table command. Adjust time window or add additional filters if results are still being capped.
- Queries match `python`, `python2`, and `python3` to cover all common interpreter names
- The `-c` flag combined with `import`, `exec`, or `eval` (Query 1) is the canonical pattern for Python-based reverse shells and payload execution. Base64-encoded payloads frequently use `__import__('base64').b64decode(...)` — the `__import__` match catches those.
- The combination of `socket` with `os.dup2` or `subprocess` in a Python command line (Query 2) is the signature of the most common Python reverse shell pattern. `pty.spawn` is used to upgrade a basic shell to a fully interactive TTY.
- Python spawned directly by apache2, nginx, or a database process (Query 3) with no corresponding application framework relationship is a strong indicator of exploitation activity
