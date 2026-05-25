# Threat Hunt: Linux Log Clearing and Tampering

## Overview

Linux systems maintain a variety of log files that record system activity, authentication events, and command execution history. These logs are a critical source of forensic data during security investigations and are frequently targeted by attackers attempting to cover their tracks after gaining access to a system.

Linux log tampering can range from outright deletion of log files to subtle manipulation of shell history files to prevent investigators from reconstructing attacker activity. Unlike Windows where clearing event logs generates a specific auditable event, Linux log tampering can be more difficult to detect and may leave fewer obvious artifacts. This hunt focuses on identifying evidence of log clearing and tampering activity on Linux systems within the environment.

---

## Hunt Hypothesis

If attackers are clearing or tampering with Linux logs to cover their tracks within the environment, evidence of that activity should appear in process execution telemetry and command-line arguments.

Potential indicators may include:

- Commands associated with bash history manipulation or suppression
- Commands used to truncate, delete, or overwrite log files under `/var/log/`
- Use of the `shred` command against log files
- Commands used to stop or disable logging services such as `rsyslog` or `auditd`

---

## Data Sources

This hunt may require visibility into the following telemetry sources:

- Linux process execution logs
- Command-line argument logging
- Auditd logs
- Centralized SIEM or log aggregation platform
- Endpoint Detection and Response (EDR) telemetry for Linux endpoints

---

## Hunt Technique 1: Bash History Manipulation

Shell history files such as `.bash_history` record commands executed in interactive terminal sessions and are a valuable source of forensic data. Attackers commonly attempt to clear or suppress bash history to prevent investigators from reviewing the commands they executed during an intrusion.

Review process execution logs and command-line telemetry for activity associated with bash history manipulation.

Common patterns to search for include:

- `history -c`
- `HISTSIZE=0`
- `HISTFILESIZE=0`
- `unset HISTFILE`
- `export HISTFILE=/dev/null`
- References to `.bash_history` in command-line arguments

Any instance of these patterns on production systems outside of expected administrative activity should be investigated promptly.

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 2: Log File Truncation and Deletion

Attackers may truncate or delete log files under `/var/log/` to remove evidence of their activity. Truncation leaves the file in place but removes its contents, which can be less immediately obvious than outright deletion. Both techniques destroy forensic data and should be treated as suspicious when observed outside of approved maintenance activity.

Review process execution logs for commands targeting log files with truncation or deletion arguments.

Common patterns to search for include:

- `truncate -s 0`
- `> /var/log/`
- `rm /var/log/`
- `rm -rf /var/log/`

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 3: Log File Overwriting with shred

The `shred` command is designed to securely overwrite files to make recovery difficult. When used against log files it overwrites their contents with random data, making forensic recovery extremely difficult. This is a more aggressive form of log tampering that may indicate a sophisticated attacker.

Review process execution logs for instances of `shred` being invoked against files under `/var/log/` or against shell history files.

Common patterns to search for include:

- `shred /var/log/`
- `shred -u /var/log/`
- `shred .bash_history`
- `shred -u .bash_history`

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 4: Stopping or Disabling Logging Services

Attackers with sufficient privileges may attempt to stop or disable logging services to prevent ongoing activity from being recorded. This approach is often observed in combination with other log clearing techniques and may indicate an attacker attempting to operate without generating new forensic artifacts.

Review process execution logs for commands used to stop or disable common Linux logging services.

Common patterns to search for include:

- `systemctl stop rsyslog`
- `systemctl stop syslog`
- `systemctl stop auditd`
- `systemctl disable rsyslog`
- `systemctl disable auditd`
- `service rsyslog stop`
- `service auditd stop`

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Investigation Considerations

If suspicious log tampering activity is identified, investigators should consider the following:

- Which user account executed the log tampering commands, and is that account expected to perform this type of activity on this system?
- Was the activity associated with an approved maintenance window or known administrative process?
- Are centralized log sources intact, or has the tampering activity affected visibility in the SIEM as well?
- Is there evidence of other suspicious activity on the affected host in close proximity to the log tampering event?
- Which specific logs or history files were targeted, and what activity may have been contained in those files prior to tampering?

Answering these questions can help determine whether the activity represents legitimate administration or an active attempt to cover attacker activity within the environment.

---

## Conclusion

Linux log clearing and tampering is a reliable indicator of post-compromise defense evasion activity on Linux systems. By monitoring for bash history manipulation, log file truncation and deletion, use of the shred command, and attempts to stop or disable logging services, defenders can detect this activity even when the underlying evidence has been destroyed. Centralized log collection and auditd deployment are essential to ensuring that tampering activity on individual endpoints does not eliminate the only copy of critical forensic data.

---

## Related Research

This threat hunt builds upon the research documented in:
- [Linux Log Clearing and Tampering in Enterprise Environments](../research/linux_log_clearing.md)
