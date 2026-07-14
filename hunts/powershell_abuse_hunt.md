# Threat Hunt: PowerShell Abuse

## Overview

PowerShell is a built-in Windows scripting language and command-line shell used by administrators to automate tasks, manage configurations, and interact with the operating system. It is natively available on virtually every modern Windows endpoint and integrates deeply with the Windows API, Active Directory, and the .NET framework.

Because PowerShell is a trusted, signed Microsoft component, attackers frequently abuse it to execute malicious code while blending in with legitimate administrative activity. It is one of the most consistently observed techniques across a wide range of intrusions, appearing at multiple stages of the attack chain including initial execution, persistence, lateral movement, and data exfiltration. This hunt focuses on identifying suspicious PowerShell activity that may indicate malicious use within the environment.

---

## Hunt Hypothesis

If attackers are abusing PowerShell to execute malicious code within the environment, evidence of that activity should appear in process creation logs, command-line arguments, and script execution events.

Potential indicators may include:

- PowerShell processes launched with encoded or obfuscated command-line arguments
- Command-line arguments referencing download cradle techniques or remote code execution
- PowerShell execution policy bypass flags present in process arguments
- PowerShell spawned by unusual or unexpected parent processes

---

## Data Sources

This hunt may require visibility into the following telemetry sources:

- Windows Event Logs (Security, System, PowerShell Operational)
- Endpoint process creation logs
- Command-line argument logging
- PowerShell Script Block Logging (Event ID 4104)
- Parent-child process relationship telemetry

---

## Hunt Technique 1: Encoded Command Execution

PowerShell supports the `-EncodedCommand` flag, which allows commands encoded in Base64 to be passed directly on the command line. While this is a legitimate feature, it is rarely used in normal administrative scripting and is frequently abused by attackers to obscure malicious command content from basic logging and string-based detection.

Review process creation events for PowerShell processes launched with encoding-related flags in the command-line arguments.

Common flags to search for include:

- `-EncodedCommand`
- `-EncodedC`
- `-EncodC`
- `-enc`
- `-ec`

Any PowerShell process launched with these flags should be reviewed to determine whether the usage is expected and authorized within the environment.


---

## Hunt Technique 2: Download Cradle Patterns

Attackers commonly use PowerShell's built-in networking capabilities to retrieve remote payloads and execute them directly in memory without writing anything to disk. These download cradles allow attackers to fetch malicious content from attacker-controlled infrastructure and execute it in a single command, bypassing many file-based detection controls.

Review process creation logs and PowerShell Script Block Logging events (Event ID 4104) for command-line arguments or script content referencing common download cradle patterns.

Strings commonly associated with download cradle activity include:

- `IEX`
- `Invoke-Expression`
- `DownloadString`
- `DownloadFile`
- `Net.WebClient`
- `Invoke-WebRequest`
- `curl`
- `wget`

These patterns should be reviewed in context. The presence of these strings alongside encoded commands or unusual parent processes significantly increases the likelihood of malicious activity.


---

## Hunt Technique 3: Execution Policy Bypass

Windows endpoints may be configured with a PowerShell execution policy that restricts script execution. Attackers commonly bypass this control by including bypass flags directly in the PowerShell command line, which overrides the policy without requiring administrative privileges or persistent changes to the system configuration.

Review process creation logs for PowerShell processes launched with execution policy bypass arguments.

Common bypass flags to search for include:

- `-ExecutionPolicy Bypass`
- `-ExecutionPolicy Unrestricted`
- `-ep bypass`
- `-ep unrestricted`

This flag combination is rarely present in legitimate administrative scripting and should be investigated when observed on endpoints outside of expected administrative systems.


---

## Hunt Technique 4: Suspicious Parent Process Relationships

In most environments, PowerShell is launched by administrators, automation frameworks, or management tooling. When PowerShell is instead spawned by Office applications, browser processes, archive utilities, or scripting engines, it is a strong indicator that a malicious document or file has been executed—commonly associated with phishing-based initial access.

Review process creation logs for PowerShell processes whose parent process is unexpected or inconsistent with normal administrative activity.

Parent processes that commonly indicate malicious activity when spawning PowerShell include:

- `winword.exe`
- `excel.exe`
- `powerpnt.exe`
- `outlook.exe`
- `mshta.exe`
- `wscript.exe`
- `cscript.exe`
- `explorer.exe` (context-dependent)

Results should be compared against the expected baseline of administrative activity within the environment to identify anomalous execution chains.


---

## Investigation Considerations

If suspicious PowerShell activity is identified, investigators should consider the following:

- Is the PowerShell activity consistent with expected administrative behavior on this endpoint?
- What parent process launched PowerShell, and is that relationship expected?
- Do the command-line arguments contain encoded content, download cradle patterns, or bypass flags?
- Is there evidence of outbound network connections following the PowerShell execution?
- Are there additional indicators of compromise on the affected host?

Answering these questions can help determine whether the activity represents legitimate administrative use or an active intrusion.

---

## Conclusion

PowerShell is one of the most versatile and widely abused tools available to attackers operating within Windows environments. By monitoring for encoded command execution, download cradle patterns, execution policy bypass flags, and anomalous parent-child process relationships, defenders can significantly improve their ability to detect malicious PowerShell activity early in the attack chain. Enabling Script Block Logging across the environment will greatly enhance visibility and improve the effectiveness of these hunt techniques.

---

## Related Research

This threat hunt builds upon the research documented in:
- [PowerShell Abuse in Enterprise Environments](../research/powershell_abuse.md)
