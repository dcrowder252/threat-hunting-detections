# Threat Hunt: Living off the Land Binary Abuse — Msiexec, Wmic, and Msbuild

## Overview

This hunt continues the Living off the Land Binary series, focusing on three Windows utilities that provide attackers with some of the most impactful capabilities observed in modern intrusion activity — msiexec.exe, wmic.exe, and msbuild.exe. These binaries enable attackers to execute code, move laterally across the network, establish persistent footholds, and bypass security controls through trusted Windows components that blend seamlessly into normal enterprise operations.

This hunt focuses on identifying suspicious usage patterns through analysis of process creation telemetry, command-line arguments, and parent-child process relationships. Given the power and versatility of these utilities, defenders should approach this hunt with particular attention to contextual indicators that distinguish malicious from legitimate usage.

---

## Hunt Hypothesis

If attackers are abusing these built-in Windows utilities to execute malicious code, move laterally, or establish persistence within the environment, evidence of that activity should appear in process creation logs and command-line argument telemetry.

Potential indicators may include:

- Msiexec invoked with remote URLs indicating external package retrieval and execution
- Msiexec spawned by Office applications, scripting engines, or browser processes
- Wmic used to invoke processes locally or on remote systems through the process call create method
- Wmic spawning child processes including scripting engines or other LOLBins
- Msbuild referencing project files in temporary directories or user-writable locations
- Msbuild executing outside of developer workstations or build servers

---

## Data Sources

This hunt may require visibility into the following telemetry sources:

- Windows Event Logs (Security — Event ID 4688 with command-line auditing enabled)
- Endpoint process creation logs
- Command-line argument logging
- Sysmon (Event ID 1 — recommended for richer command-line and parent process visibility)
- Network connection telemetry

---

## Hunt Technique 1: Msiexec Remote Package Execution

Msiexec is the Windows Installer engine that is invoked constantly in enterprise environments for legitimate software installation. Attackers abuse msiexec to execute malicious MSI packages silently and to fetch and execute packages directly from remote URLs — providing a download and execute capability through a fully trusted system binary. The `/quiet` and `/norestart` flags are commonly used alongside malicious invocations to suppress any user interface and prevent system restarts that might alert the user.

Hunt for msiexec process creation events where the command-line arguments reference external URLs rather than local file paths or internal network shares. Also hunt for msiexec invocations that include the `/quiet` flag in conjunction with references to external locations or unexpected file paths.

Related detections that may be observed in conjunction with this activity:

- Microsoft Defender for Endpoint — Suspicious msiexec activity
- Microsoft Defender for Endpoint — Software installation from unusual location

---

## Hunt Technique 2: Msiexec Spawned by Suspicious Parent Process

In phishing-based intrusion scenarios, msiexec is commonly spawned by Office applications, scripting engines, or browser processes as part of a malicious document or file execution chain. The parent process relationship is one of the most reliable indicators for distinguishing malicious from legitimate msiexec usage, as legitimate software deployment typically involves dedicated deployment tool parent processes rather than productivity applications.

Hunt for msiexec process creation events where the parent process is an Office application, scripting engine, browser, or archive utility rather than a legitimate software deployment tool.

Related detections that may be observed in conjunction with this activity:

- Microsoft Defender for Endpoint — Office application spawning installer process
- Microsoft Defender for Endpoint — Suspicious process chain

---

## Hunt Technique 3: Wmic Remote Process Execution and Lateral Movement

Wmic provides a command-line interface to the Windows Management Instrumentation infrastructure and is one of the most powerful lateral movement tools available to attackers through native Windows functionality. The `process call create` method allows wmic to execute processes on both local and remote systems using valid credentials without deploying any additional tooling to the target. This capability is rarely used in legitimate administrative scenarios outside of specific management frameworks and should be treated as suspicious when observed outside of those expected contexts.

Hunt for wmic process creation events where the command-line arguments contain the `process call create` method, particularly when combined with remote target specifications or unusual command references. Pay particular attention to wmic invocations that include references to remote systems, scripting engines, or other LOLBins in the command being executed.

> **Note:** As of the September 2026 Security Update, wmic.exe has been removed from Windows 11 versions 24H2 and 25H2. Detection coverage remains important for environments running older Windows versions where wmic.exe is still present. See the research paper for full context on the deprecation timeline.

Related detections that may be observed in conjunction with this activity:

- Microsoft Defender for Endpoint — WMI lateral movement
- Microsoft Defender for Endpoint — Suspicious WMI activity

---

## Hunt Technique 4: Wmic Spawning Suspicious Child Processes

Wmic is frequently used as an execution proxy where it spawns other processes including scripting engines, PowerShell, or other LOLBins. This technique obscures the origin of malicious execution by interposing wmic between the initial execution trigger and the ultimate payload. Monitoring for processes spawned as children of wmic can surface these execution chains regardless of what specific command was used to invoke wmic.

Hunt for process creation events where wmic is the parent process and the child process is a scripting engine, command interpreter, PowerShell, or another LOLBin.

Related detections that may be observed in conjunction with this activity:

- Microsoft Defender for Endpoint — Suspicious WMI child process
- Microsoft Defender for Endpoint — Suspicious process injection

---

## Hunt Technique 5: Msbuild Executing Inline Code from Suspicious Locations

Msbuild is the Microsoft Build Engine included with the .NET Framework. Attackers abuse it by crafting malicious project files containing inline C# or Visual Basic code that is compiled and executed in memory when msbuild processes the file. This technique produces minimal disk artifacts and leverages a signed trusted Microsoft binary. Legitimate msbuild usage is well-defined in most enterprise environments — it occurs on developer workstations and build servers, invoked by development tools and CI/CD pipelines. Any msbuild execution outside of these expected contexts warrants investigation.

Hunt for msbuild process creation events where the command-line arguments reference project files in temporary directories, user-writable locations, or remote locations including external URLs or UNC paths rather than standard development project directories. Also hunt for msbuild execution on endpoints that are not developer workstations or build servers.

Related detections that may be observed in conjunction with this activity:

- Microsoft Defender for Endpoint — Suspicious msbuild activity
- Microsoft Defender for Endpoint — Trusted developer utility executing suspicious code

---

## Investigation Considerations

If suspicious LOLBin activity is identified, investigators should consider the following:

- What parent process spawned the binary and is that relationship expected in the environment?
- Do the command-line arguments reference external URLs, remote systems, or non-standard file paths?
- Is there evidence of outbound network connections from the process following execution?
- Was a file written to disk as a result of the activity and if so what is its content and location?
- In the case of wmic activity — is there evidence of lateral movement to other systems and were valid credentials used?
- In the case of msbuild activity — is the endpoint a developer workstation or build server and is the project file path consistent with legitimate development activity?
- Is there evidence of follow-on execution or persistence mechanisms established following the initial LOLBin invocation?

---

## Conclusion

Msiexec, wmic, and msbuild represent some of the most capable and impactful LOLBins available to attackers through native Windows functionality. The remote package execution capability of msiexec, the lateral movement and persistence potential of wmic, and the in-memory code execution capability of msbuild each address different phases of the attack lifecycle and are observed across a wide range of threat actor categories. While wmic.exe is being progressively removed from modern Windows 11 installations, the majority of enterprise endpoint populations will include systems where it remains present for the foreseeable future. By hunting for remote URL references in msiexec invocations, process call create usage in wmic, suspicious child processes spawned by wmic, and msbuild project file execution outside of expected development contexts, defenders can surface LOLBin abuse that might otherwise blend into the background of legitimate administrative activity.


