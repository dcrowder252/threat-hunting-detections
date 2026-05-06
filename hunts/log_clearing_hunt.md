# Threat Hunt: Windows Event Log Clearing

## Overview

Windows Event Logs provide critical visibility into system activity across enterprise endpoints. Security teams rely on these logs to detect threats, investigate incidents, and reconstruct attacker activity. Because of this, attackers frequently clear event logs as part of their effort to cover their tracks and hinder forensic investigation.

While log clearing can occur for legitimate administrative reasons, it is a well-established defense evasion technique that warrants immediate investigation when observed outside of an approved maintenance process. This hunt focuses on identifying evidence of event log clearing activity within the environment, including both the clearing events themselves and the command-line activity associated with programmatic log clearing.

---

## Hunt Hypothesis

If attackers are clearing Windows Event Logs to cover their tracks within the environment, evidence of that activity should appear in remaining log data and process creation telemetry.

Potential indicators may include:

- Windows Event ID 1102 indicating the Security audit log was cleared
- Windows Event ID 104 indicating a Windows Event Log was cleared
- Process creation events showing wevtutil invoked with log clearing arguments
- PowerShell activity referencing the Clear-EventLog cmdlet

---

## Data Sources

This hunt may require visibility into the following telemetry sources:

- Windows Event Logs (Security, System)
- Endpoint process creation logs
- Command-line argument logging
- PowerShell Script Block Logging (Event ID 4104)
- Centralized SIEM or log aggregation platform

---

## Hunt Technique 1: Security Log Clearing (Event ID 1102)

Windows Event ID 1102 is generated in the Security log whenever the Security audit log is cleared. This is one of the most significant log clearing events in a Windows environment because the Security log is the primary source of authentication, logon, and privilege use activity. Clearing this log removes evidence of potentially critical attacker actions.

Review the Security log for the presence of Event ID 1102. Each occurrence includes the username and logon session of the account that performed the clearing action, which provides valuable context for triage and investigation.

Any instance of Event ID 1102 outside of a known and approved maintenance window should be treated as suspicious and investigated promptly.

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 2: System and Application Log Clearing (Event ID 104)

Windows Event ID 104 is generated in the System log whenever any Windows Event Log is cleared through the Event Log service. This event captures clearing of the System, Application, and other logs beyond the Security log. Like Event ID 1102, it records the account responsible for the action.

Review the System log for the presence of Event ID 104. Pay particular attention to the log name field within the event, which identifies which specific log was cleared.

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 3: Wevtutil Log Clearing

The `wevtutil` command-line utility is one of the most commonly observed tools used by attackers for programmatic log clearing. When invoked with the `cl` or `clear-log` argument, it can clear any Windows Event Log from the command line and is well suited for scripted or automated post-exploitation activity.

Review process creation logs for instances of `wevtutil` being invoked with log clearing arguments.

Common command patterns to search for include:

- `wevtutil cl`
- `wevtutil clear-log`

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 4: PowerShell-Based Log Clearing

PowerShell provides the `Clear-EventLog` cmdlet as a built-in method for clearing Windows Event Logs programmatically. This method is commonly observed in intrusions where PowerShell is already being leveraged for other stages of the attack chain.

Review process creation logs and PowerShell Script Block Logging events (Event ID 4104) for references to log clearing cmdlets and methods.

Strings commonly associated with PowerShell-based log clearing include:

- `Clear-EventLog`
- `ClearEventLog`
- `System.Diagnostics.EventLog`

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Investigation Considerations

If log clearing activity is identified, investigators should consider the following:

- Was the log clearing activity associated with an approved maintenance window or known administrative process?
- Which account performed the clearing action, and is that account expected to perform this type of activity?
- Which logs were cleared, and what activity may have been contained in those logs prior to clearing?
- Is there evidence of other suspicious activity on the affected host in close proximity to the log clearing event?
- Are centralized log sources intact, or has the clearing activity affected visibility in the SIEM as well?

Answering these questions can help determine whether the activity represents legitimate administration or an active attempt to cover attacker activity within the environment.

---

## Conclusion

Windows Event Log clearing is a reliable indicator of post-compromise defense evasion activity. While the cleared logs themselves may be unrecoverable, the act of clearing generates specific and detectable artifacts that defenders can monitor. By hunting for Event IDs 1102 and 104 alongside command-line evidence of wevtutil and PowerShell-based log clearing, security teams can detect this activity even when the underlying evidence has been destroyed. Centralized log collection is essential to ensuring that clearing activity on individual endpoints does not eliminate the only copy of critical forensic data.

---

## Related Research

This threat hunt builds upon the research documented in:
- [Windows Event Log Clearing in Enterprise Environments](../research/log_clearing.md)
