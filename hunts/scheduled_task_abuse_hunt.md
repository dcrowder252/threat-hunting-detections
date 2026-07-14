# Threat Hunt: Scheduled Task Abuse

## Overview

Scheduled Tasks are a native Windows feature used by administrators to automate the execution of programs and scripts at defined times or in response to system events. They are a common and expected part of most enterprise environments, used for everything from software updates to routine maintenance operations.

Because Scheduled Tasks provide a reliable, persistent, and native execution mechanism, they are frequently abused by attackers to maintain access to compromised systems and execute malicious payloads. Malicious tasks can be configured to survive reboots, run under highly privileged accounts, and execute encoded or obfuscated commands — making them an effective and stealthy persistence mechanism. This hunt focuses on identifying evidence of suspicious scheduled task creation, modification, and execution within the environment.

---

## Hunt Hypothesis

If attackers are abusing Scheduled Tasks to establish persistence or execute malicious code within the environment, evidence of that activity should appear in Windows event logs, process creation telemetry, and command-line arguments.

Potential indicators may include:

- Windows Event ID 4698 indicating a new scheduled task was created
- Windows Event ID 4702 indicating an existing scheduled task was modified
- Process creation events showing schtasks.exe invoked with creation or modification arguments
- PowerShell activity referencing scheduled task registration cmdlets
- Scheduled tasks configured to execute from non-standard paths or with encoded command-line arguments

---

## Data Sources

This hunt may require visibility into the following telemetry sources:

- Windows Event Logs (Security)
- Endpoint process creation logs
- Command-line argument logging
- PowerShell Script Block Logging (Event ID 4104)
- Centralized SIEM or log aggregation platform

---

## Important Note on Audit Policy

Windows Event IDs 4698 and 4702 are not enabled by default on all Windows systems. These events require the **Audit Other Object Access Events** policy to be configured under Advanced Audit Policy Configuration. Organizations that have not enabled this policy will have significantly reduced visibility into scheduled task creation and modification activity. Enabling this audit policy should be treated as a priority for any environment looking to detect scheduled task abuse.

---

## Hunt Technique 1: Scheduled Task Creation (Event ID 4698)

Windows Event ID 4698 is generated in the Security log whenever a new scheduled task is created. This event contains the full XML definition of the task including its name, trigger, action, and the account used to register it. Reviewing newly created tasks against the expected baseline for the environment can help surface malicious task registrations.

Pay particular attention to tasks that meet any of the following criteria:

- Created by unexpected or non-administrative accounts
- Configured to run as the SYSTEM account
- Referencing unusual execution paths such as temporary directories or user profile folders
- Containing encoded commands or references to scripting engines in the task action

NOTE: A scheduled task configured to run as SYSTEM is a particularly high fidelity indicator. Creating a task that runs under the SYSTEM account requires administrative privileges, which means the attacker has already achieved a significant level of access within the environment before establishing this persistence mechanism.


---

## Hunt Technique 2: Scheduled Task Modification (Event ID 4702)

Windows Event ID 4702 is generated whenever an existing scheduled task is updated. Some attackers prefer to modify existing legitimate tasks rather than creating new ones, as this technique can be harder to detect — the task itself may appear familiar and trusted at first glance.

Review Event ID 4702 for unexpected modifications to scheduled tasks, particularly changes to the task action, trigger, or execution context. Modifications made outside of known software deployment or maintenance windows should be treated as suspicious.


---

## Hunt Technique 3: Schtasks.exe Process Execution

The built-in `schtasks.exe` command-line utility allows users to create, modify, delete, and query scheduled tasks from the command line. Attackers frequently use this utility to register malicious tasks programmatically, making it well suited for scripted or automated post-exploitation activity.

Review process creation logs for instances of `schtasks.exe` invoked with task creation or modification arguments.

Common arguments to search for include:

- `/create`
- `/change`

Pay particular attention to the full command-line arguments accompanying these flags, as they may reveal the task name, execution path, and any encoded or obfuscated content being registered.


---

## Hunt Technique 4: PowerShell-Based Task Registration

PowerShell provides built-in cmdlets for creating and managing scheduled tasks programmatically. These cmdlets are commonly observed in intrusions where PowerShell is already being leveraged for other stages of the attack chain, and may be used to register tasks that execute encoded payloads or download additional tooling.

Review process creation logs and PowerShell Script Block Logging events (Event ID 4104) for references to scheduled task registration cmdlets.

Strings commonly associated with PowerShell-based task registration include:

- `Register-ScheduledTask`
- `New-ScheduledTaskAction`
- `New-ScheduledTask`
- `Set-ScheduledTask`


---

## Investigation Considerations

If suspicious scheduled task activity is identified, investigators should consider the following:

- Is the scheduled task associated with a known and approved application or administrative process?
- Which account created or modified the task, and does that account have a legitimate reason to manage scheduled tasks?
- Is the task configured to run as SYSTEM or another highly privileged account? If so, how did the creating account obtain the privileges necessary to register a SYSTEM task?
- Does the task action reference an unusual execution path, a scripting engine, or encoded command-line arguments?
- Is there evidence of other suspicious activity on the affected host in close proximity to the task creation or modification event?

Answering these questions can help determine whether the activity represents legitimate administrative use or an active attempt to establish persistence within the environment.

---

## Conclusion

Scheduled Tasks are one of the most commonly abused persistence mechanisms in Windows environments. While the volume of legitimate scheduled task activity can make detection challenging, monitoring for newly created and modified tasks alongside command-line evidence of schtasks.exe and PowerShell-based task registration gives defenders strong visibility into this technique. Tasks configured to run as SYSTEM should be treated as especially high priority, as their creation implies the attacker has already achieved significant privilege within the environment. Establishing a baseline of approved scheduled tasks is essential to making these detections operationally effective.

---

## Related Research

This threat hunt builds upon the research documented in:
- [Scheduled Task Abuse in Enterprise Environments](../research/scheduled_task_abuse.md)
