# Threat Hunt: Linux Scheduled Task Abuse

## Overview

Linux provides several native mechanisms for scheduling automated task execution including cron and systemd timers. These tools are widely used across enterprise Linux environments for legitimate administrative and application tasks, making them a natural target for attackers seeking to establish persistent access that blends into normal system activity.

Malicious cron jobs and systemd timers can be created at multiple privilege levels, from user-level crontabs that require no administrative access to system-wide cron directories and systemd unit files that require root privileges. Once established, these persistence mechanisms execute automatically according to their defined schedule without requiring the attacker to maintain an active connection to the system. This hunt focuses on identifying evidence of suspicious scheduled task creation and modification on Linux systems within the environment.

---

## Hunt Hypothesis

If attackers are abusing Linux scheduled task mechanisms to establish persistence or execute malicious code within the environment, evidence of that activity should appear in process execution telemetry, command-line arguments, and file system activity.

Potential indicators may include:

- Invocations of the `crontab` command with creation or modification arguments
- File creation or modification events in cron-related directories or files
- Creation of new systemd timer or service unit files in systemd directories
- Cron job content referencing unusual execution paths, scripting engines, or encoded commands

---

## Data Sources

This hunt may require visibility into the following telemetry sources:

- Linux process execution logs
- Command-line argument logging
- File integrity monitoring telemetry
- Auditd logs
- Centralized SIEM or log aggregation platform
- Endpoint Detection and Response (EDR) telemetry for Linux endpoints

---

## Hunt Technique 1: Crontab Modification Commands

The `crontab` command allows users to create and manage their own scheduled jobs without requiring administrative privileges. Attackers commonly use `crontab -e` to add malicious entries to a user's crontab or `crontab -r` to remove existing entries as part of cleanup activity.

Review process execution logs for invocations of the `crontab` command with modification or removal arguments.

Common arguments to search for include:

- `crontab -e`
- `crontab -r`
- `crontab -l`

Pay particular attention to crontab modifications on systems where interactive user activity is not expected such as servers and cloud workloads. Review the crontab content where possible to identify suspicious entries referencing unusual binaries, encoded commands, or network connections.

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 2: Writes to System Cron Directories and Files

Root-level cron jobs can be placed in several system-wide locations. Attackers with root access may drop malicious scripts into these directories to establish persistent execution under the root account. Monitoring for unexpected file creation or modification in these locations can surface malicious cron entries introduced outside of approved software deployment processes.

Locations to monitor include:

- `/etc/cron.d/`
- `/etc/cron.daily/`
- `/etc/cron.hourly/`
- `/etc/cron.weekly/`
- `/etc/cron.monthly/`
- `/etc/crontab`
- `/var/spool/cron/crontabs/`

Any new or modified files in these locations outside of known software deployment or maintenance windows should be reviewed for suspicious content.

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 3: Systemd Timer and Service Unit Creation

Systemd timers consist of a `.timer` unit file paired with a `.service` unit file and are managed through the systemd service manager. Attackers may create malicious timer and service unit files to establish persistent execution that integrates with the systemd framework and survives reboots.

Monitor for the creation of new `.timer` or `.service` unit files in systemd directories.

Locations to monitor include:

- `/etc/systemd/system/`
- `/usr/lib/systemd/system/`
- `/run/systemd/system/`

Review newly created unit files for suspicious content including references to unusual binaries, encoded commands, download cradles, or outbound network connections. Also monitor for `systemctl enable` commands used to activate newly created timer units.

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 4: Suspicious Cron Job Content

In addition to monitoring for the creation of cron entries, reviewing the content of existing cron jobs for suspicious patterns can help identify malicious scheduled tasks that may have already been established. This is particularly valuable during incident investigations where persistence may have been in place for an extended period before detection.

Review cron job definitions across all cron directories and user crontabs for entries containing:

- References to scripting engines such as `bash`, `python`, `perl`, or `php` executing content from unusual paths
- Encoded commands or base64 strings
- Download cradle patterns such as `curl`, `wget`, or references to remote URLs
- References to temporary directories such as `/tmp/` or `/dev/shm/`
- Entries running under the root account that were not deployed through approved processes

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Investigation Considerations

If suspicious scheduled task activity is identified, investigators should consider the following:

- Which user account created or modified the cron job or systemd unit, and does that account have a legitimate reason to manage scheduled tasks on this system?
- Is the scheduled task associated with a known and approved application or administrative process?
- Does the task content reference unusual execution paths, encoded commands, or external resources?
- Was the task created or modified outside of a known software deployment or maintenance window?
- Is there evidence of other suspicious activity on the affected host in close proximity to the scheduled task creation event?

Answering these questions can help determine whether the activity represents legitimate administrative use or an active attempt to establish persistence within the environment.

---

## Conclusion

Cron and systemd timers are among the most commonly abused persistence mechanisms on Linux systems. The variety of locations where cron jobs can be defined and the ability to create user-level jobs without administrative privileges make comprehensive detection challenging. By monitoring for crontab modification commands, writes to system cron directories, creation of systemd timer units, and suspicious cron job content, defenders can significantly improve their ability to detect scheduled task abuse across Linux environments. Establishing a baseline of legitimate scheduled task activity is essential to making these detections operationally effective.

---

## Related Research

This threat hunt builds upon the research documented in:
- [Linux Scheduled Task Abuse in Enterprise Environments](../research/linux_scheduled_task_abuse.md)
