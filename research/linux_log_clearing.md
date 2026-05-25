# Linux Log Clearing and Tampering in Enterprise Environments

## Overview

Linux systems maintain a variety of log files that record system activity, authentication events, command execution, and application behavior. These logs are stored primarily under the `/var/log/` directory and are a critical source of forensic data during security investigations. Common log files include `auth.log` or `secure` for authentication events, `syslog` for general system activity, `messages` for kernel and system messages, and shell history files such as `.bash_history` that record commands executed by users in interactive sessions.

Because Linux logs provide defenders with visibility into user activity, privilege escalation attempts, lateral movement, and other attacker behaviors, they are frequently targeted by attackers as part of their effort to cover their tracks and hinder forensic investigation. Linux log tampering can take many forms — from outright deletion of log files to subtle manipulation of shell history files to prevent investigators from reconstructing attacker activity. Understanding how Linux logs are commonly tampered with and what artifacts that activity leaves behind is an important part of building detection capability in environments that include Linux endpoints, servers, and cloud workloads.

---

## Why Attackers Target Linux Logs

Linux environments are increasingly prevalent across enterprise infrastructure — from web servers and database hosts to cloud workloads, containers, and developer endpoints. Many of these systems hold sensitive data or provide access to critical services, making them high value targets for attackers. Once access is gained, attackers frequently attempt to clear or manipulate logs to remove evidence of their initial access method, the commands they executed, the files they accessed, and any lateral movement activity.

Linux shell history files are particularly attractive targets because they provide a near real-time record of commands executed by a user in an interactive session. Clearing or manipulating bash history can remove direct evidence of attacker commands including those used for reconnaissance, credential access, data exfiltration, and persistence establishment. Unlike Windows Event Logs where clearing generates a specific auditable event, Linux log manipulation can be more subtle — attackers may truncate files, redirect output to `/dev/null`, or manipulate environment variables to prevent history from being written at all.

Log tampering on Linux is also sometimes observed as part of broader destructive activity, where attackers attempt to maximize the difficulty of incident response by eliminating as many forensic artifacts as possible before deploying ransomware or other destructive payloads.

---

## Common Log Tampering Techniques

The following techniques represent some of the most frequently observed methods of Linux log tampering in security incidents and public threat intelligence reporting. This list is not exhaustive, as attackers continue to develop new variations and evasion approaches over time.

**Bash History Manipulation**

Shell history files such as `.bash_history` record commands executed in interactive terminal sessions and are a valuable source of forensic data. Attackers commonly attempt to clear or manipulate this file using several methods including the `history -c` command to clear the in-memory history, setting the `HISTSIZE` or `HISTFILESIZE` environment variables to zero to prevent history from being retained, unsetting the `HISTFILE` variable to prevent history from being written to disk, or directly deleting or overwriting the `.bash_history` file.

**Log File Deletion or Truncation**

Attackers may delete log files under `/var/log/` entirely or truncate them to remove their contents while leaving the file in place. Truncation using commands such as `truncate -s 0` or by redirecting to the file with `> /var/log/filename` removes log content without deleting the file itself, which can be less immediately obvious than outright deletion.

**Log File Overwriting with shred**

The `shred` command is designed to securely overwrite files to make recovery difficult. When used against log files, it overwrites the file contents with random data, making forensic recovery of the original log content extremely difficult. This is a more aggressive form of log tampering that may indicate a sophisticated attacker attempting to prevent any recovery of deleted log data.

**Disabling or Stopping Logging Services**

Attackers with sufficient privileges may attempt to stop or disable logging services such as `syslog`, `rsyslog`, or `auditd` to prevent new log entries from being generated. This approach prevents ongoing activity from being recorded rather than removing existing evidence, and may be observed in combination with other log clearing techniques.

---

## The Operational Problem

One of the core challenges with Linux log tampering detection is the diversity of logging configurations across Linux environments. Unlike Windows where Event Log behavior is relatively standardized, Linux logging can vary significantly depending on the distribution, the installed logging daemon, and the specific configuration applied by the organization. Some environments use `rsyslog`, others use `syslog-ng` or `journald`, and logging configurations can vary widely even within the same organization.

Centralized log collection is even more critical in Linux environments than in Windows environments. If logs are only stored locally on the endpoint, an attacker with sufficient access can destroy them entirely and eliminate the primary forensic record of their activity. Organizations that forward Linux logs to a centralized SIEM in near real time are significantly better positioned to retain forensic data even when local log files have been tampered with or destroyed.

Shell history files present a particular challenge because they are user-controlled by design. Standard users can manipulate their own history files without requiring elevated privileges, which means that even non-privileged attackers can cover their command-line tracks. Defenders should consider enabling centralized command auditing through tools such as `auditd` or shell logging solutions that capture command execution independently of the shell history mechanism.

---

## Detection Opportunities

Effective detection of Linux log tampering relies on a combination of process execution monitoring, file integrity monitoring, and centralized log collection. The following opportunities represent practical starting points for hunting and detection.

**Monitor for shell history manipulation commands**

Searching process execution logs for commands associated with bash history manipulation — including `history -c`, modifications to `HISTFILE`, `HISTSIZE`, or `HISTFILESIZE`, and direct access to `.bash_history` files — can help identify attempts to cover command-line activity.

**Detect log file truncation and deletion**

Monitoring for commands such as `truncate`, `shred`, and direct redirection to log files under `/var/log/` can surface attempts to destroy or overwrite log content. Process execution monitoring with command-line argument visibility is essential for detecting these techniques.

**Monitor for stopping or disabling logging services**

Commands used to stop or disable logging services such as `systemctl stop rsyslog`, `systemctl disable auditd`, or `service syslog stop` may indicate an attacker attempting to prevent ongoing activity from being recorded. Monitoring for these commands on production systems outside of approved maintenance windows should be treated as suspicious.

**Implement centralized log forwarding**

Forwarding Linux logs to a centralized SIEM in near real time is the most effective mitigation against log tampering. Even when local log files are destroyed, centrally collected logs retain the forensic record up to the point of the tampering event. This should be treated as a foundational security control rather than an optional enhancement.

**Enable auditd for command execution visibility**

The Linux Audit daemon (`auditd`) provides detailed visibility into system calls, file access, and process execution that is independent of shell history. Enabling and properly configuring `auditd` significantly improves the ability to detect log tampering and other suspicious activity on Linux systems.

---

## MITRE ATT&CK Mapping

Linux log clearing and tampering is categorized as:

**T1070.003 – Indicator Removal: Clear Command History**

https://attack.mitre.org/techniques/T1070/003/

**T1070.002 – Indicator Removal: Clear Linux or Mac System Logs**

https://attack.mitre.org/techniques/T1070/002/

---

## Sources

- https://attack.mitre.org/techniques/T1070/003/
- https://attack.mitre.org/techniques/T1070/002/
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a
- https://linux.die.net/man/8/auditd
- https://redcanary.com/threat-detection-report/techniques/indicator-removal/
