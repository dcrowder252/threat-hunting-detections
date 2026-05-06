# Windows Event Log Clearing in Enterprise Environments

## Overview

Windows Event Logs are a critical component of the operating system's built-in auditing and monitoring capabilities. They record a wide range of system activity including user logons, process creation, service installations, policy changes, and security-related events. Security teams rely heavily on these logs for incident detection, investigation, and response. Without event log data, reconstructing the timeline of an intrusion or identifying the scope of malicious activity becomes significantly more difficult.

Because of this, attackers frequently target Windows Event Logs as part of their effort to cover their tracks and hinder forensic investigation. Clearing event logs removes evidence of prior activity — including the very actions that may have triggered a security alert in the first place. While log clearing can occur for legitimate administrative reasons, it is a well-established attacker behavior that warrants immediate investigation when observed in an enterprise environment. Defenders who understand how log clearing works and what artifacts it leaves behind are better positioned to detect and respond to this activity quickly.

---

## Why Attackers Clear Logs

Log clearing is fundamentally a defense evasion technique. After gaining access to a system, attackers may clear event logs to remove evidence of their initial access, lateral movement, credential access attempts, or other malicious activity. By eliminating this data, they make it significantly harder for defenders to determine what happened, when it happened, and how far the attacker progressed through the environment.

In many intrusions, log clearing is observed late in the attack chain — after an attacker has already achieved their objectives and is attempting to minimize the forensic footprint left behind. However, some attackers clear logs early and repeatedly throughout an intrusion to maintain operational security and reduce the likelihood of detection. In either case, the act of clearing logs is itself a detectable event, which creates an important detection opportunity for defenders even when the underlying malicious activity has been erased.

Log clearing is also sometimes used as a disruptive technique in destructive attacks, where the goal is not just to evade detection but to deny defenders access to the visibility they need to respond effectively. In these scenarios, log clearing may be performed alongside other destructive actions such as ransomware deployment or data destruction.

---

## How Logs Are Cleared

Windows provides several built-in mechanisms for clearing event logs, all of which are accessible to users with sufficient privileges. The most common methods observed in security incidents include the Windows Event Viewer graphical interface, the `wevtutil` command-line utility, and PowerShell cmdlets such as `Clear-EventLog`. Each of these methods produces slightly different artifacts, but all result in the generation of specific Windows Event IDs that can be monitored by defenders.

Attackers frequently use `wevtutil` because it allows all event logs to be cleared programmatically from the command line with a single command, making it well suited for scripted or automated post-exploitation activity. PowerShell-based log clearing is also commonly observed, particularly in intrusions where PowerShell is already being used for other stages of the attack chain. In some cases, attackers may attempt to clear only specific logs — such as the Security log — to remove targeted evidence while leaving other logs intact.

It is worth noting that clearing event logs typically requires administrative privileges. The presence of log clearing activity therefore implies that the attacker has already achieved a significant level of access within the environment, which further increases the urgency of investigating this activity when it is detected.

---

## The Operational Problem

One of the core challenges with log clearing as a detection signal is that it can also occur for legitimate reasons in some environments. System administrators may clear logs as part of routine maintenance, troubleshooting, or log management workflows. In environments without centralized log collection or a SIEM, local log clearing may go unnoticed entirely. This makes it especially important for organizations to ship event logs to a central location in near real time — if logs are only stored locally, an attacker who clears them also eliminates the only copy of that data.

Organizations that have not implemented centralized log collection face a significant disadvantage when investigating intrusions where log clearing has occurred. Even when logs are forwarded to a SIEM, there may be delays in ingestion that allow an attacker to clear logs before all events have been shipped. Understanding the log forwarding latency in the environment is an important consideration when building detections around log clearing activity.

Establishing a baseline of legitimate log clearing activity is also essential. In most enterprise environments, routine administrative clearing of the Security or System log is rare or nonexistent. Any instance of log clearing on an endpoint outside of a known maintenance window or approved administrative process should be treated as suspicious and investigated promptly.

---

## Detection Opportunities

Despite its destructive nature, log clearing leaves behind specific and reliable artifacts that defenders can monitor. The act of clearing a log is itself recorded as a Windows Event, which provides a detection opportunity even when the cleared log contained evidence of malicious activity.

**Monitor for Security log clearing (Event ID 1102)**

Windows Event ID 1102 is generated in the Security log whenever the Security audit log is cleared. This event includes the username and logon session of the account that performed the action, providing valuable context for investigation. Clearing the Security log is particularly significant because it is the primary source of authentication and logon activity on Windows systems.

**Monitor for System and other log clearing (Event ID 104)**

Windows Event ID 104 is generated in the System log whenever any event log is cleared using the Event Log service. This event captures clearing of the System, Application, and other logs. Like Event ID 1102, it includes information about the account responsible for the action.

**Hunt for wevtutil log clearing commands**

The `wevtutil` utility with the `cl` or `clear-log` argument is one of the most commonly observed methods for programmatic log clearing. Monitoring process creation events for `wevtutil` invocations with these arguments can identify scripted or automated log clearing activity.

**Detect PowerShell-based log clearing**

PowerShell's `Clear-EventLog` cmdlet provides another method for clearing logs programmatically. Monitoring Script Block Logging events and process creation logs for references to this cmdlet can surface PowerShell-based log clearing attempts.

**Correlate log clearing with other suspicious activity**

Log clearing observed in isolation may have a legitimate explanation. However, log clearing that occurs in close temporal proximity to other suspicious activity — such as lateral movement, credential access, or ransomware precursor behaviors — significantly increases the likelihood of malicious intent and should be escalated immediately.

---

## MITRE ATT&CK Mapping

Windows Event Log clearing is categorized as:

**T1070.001 – Indicator Removal: Clear Windows Event Logs**

https://attack.mitre.org/techniques/T1070/001/

---

## Sources

- https://attack.mitre.org/techniques/T1070/001/
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a
- https://redcanary.com/threat-detection-report/techniques/indicator-removal/
- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102

## Threat Hunt
