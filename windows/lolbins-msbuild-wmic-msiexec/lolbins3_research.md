# Living off the Land Binary Abuse — Msiexec, Wmic, and Msbuild

## Overview

This document continues the Living off the Land Binary series, focusing on three additional Windows utilities that are consistently observed in security incidents across a wide range of threat actor categories — msiexec.exe, wmic.exe, and msbuild.exe. Each of these binaries provides attackers with distinct and powerful capabilities that extend well beyond the execution and download techniques covered in previous installments of this series. Together they represent some of the most impactful LOLBin abuse techniques observed in modern intrusion activity, enabling attackers to execute code, move laterally, establish persistence, and bypass security controls through trusted and expected Windows components.

---

## Why These Binaries Matter

The three utilities covered in this document are not merely convenient alternatives to custom malware — they represent foundational capabilities that are deeply integrated into how Windows environments operate. Msiexec is the backbone of Windows software installation. Wmic is a powerful management interface that has been built into Windows for decades. Msbuild is a core component of the Microsoft development ecosystem. Each is trusted, expected, and in many environments actively used for legitimate purposes on a daily basis. This combination of ubiquity, trust, and powerful functionality makes them exceptionally attractive to attackers and exceptionally challenging to defend against through traditional means.

---

## Commonly Abused Binaries

The following represents a sampling of abuse techniques associated with these utilities as observed in security incidents and threat intelligence reporting. This is not an exhaustive list, as attacker tradecraft continues to evolve.

**msiexec.exe**

Msiexec is the Windows Installer engine responsible for installing, modifying, and removing software packaged in MSI format. It is a signed Microsoft binary present on all modern Windows installations and is invoked constantly in enterprise environments by software deployment tools, patch management systems, and manual software installations. Attackers abuse msiexec in several ways. Most directly, msiexec can be used to execute malicious MSI packages that install and run attacker-controlled payloads while appearing to perform a normal software installation. More significantly, msiexec can fetch and execute MSI packages from remote URLs using the `/i` flag followed by a web address — providing a download and execute capability that leverages a fully trusted system binary. Msiexec can also be combined with the `/quiet` and `/norestart` flags to suppress any user interface or system restart prompts, allowing silent payload execution. Because msiexec is signed by Microsoft and performs actions that are indistinguishable from legitimate software installation at the binary level, it is frequently used in phishing campaigns and post-exploitation scenarios for payload delivery and execution.

**wmic.exe**

The Windows Management Instrumentation Command-line utility provides a command-line interface to the Windows Management Instrumentation infrastructure, which is one of the most powerful management frameworks built into Windows. WMI allows administrators to query system information, manage processes, interact with the registry, and perform actions on both local and remote systems. Attackers have abused wmic for decades across virtually every phase of an intrusion. For execution, wmic can invoke processes on both local and remote systems using the `process call create` method, providing a powerful remote execution capability that does not require the creation of new services or scheduled tasks. For reconnaissance, wmic provides rich system information that attackers use to understand the target environment. For persistence, wmic event subscriptions can be used to execute code in response to system events — a technique that survives reboots and is notoriously difficult to detect and remove. Lateral movement via wmic is particularly significant because the remote process execution capability allows attackers to move between systems using only built-in Windows functionality and valid credentials, without deploying any additional tooling to remote targets.

**A Note on WMIC Deprecation and Removal**

Microsoft has officially removed wmic.exe from Windows 11 versions 24H2 and 25H2 as part of the September 2026 Security Update, completing a deprecation process that began in 2021. The underlying Windows Management Instrumentation infrastructure remains fully intact and available through PowerShell and other interfaces — only the wmic.exe command-line utility itself is being removed. This change was driven in part by the extensive abuse of wmic as a LOLBin by threat actors including ransomware operators who used it to delete Shadow Volume Copies, query and uninstall security software, and add exclusions to Microsoft Defender.

Despite this removal, detection coverage for wmic abuse remains important for several reasons. The majority of enterprise environments include a significant population of endpoints running older Windows versions where wmic.exe remains present. Organizations with managed estates that have not yet migrated to Windows 11 24H2 or later will continue to have wmic.exe available on their endpoints for the foreseeable future. Additionally, wmic.exe can in some configurations still be restored as a Feature on Demand, and legacy scripts and tooling that depend on it may create pressure to keep it available in some environments. Defenders should continue to monitor for wmic abuse while also tracking the gradual reduction in its availability across their endpoint population.

**msbuild.exe**

MSBuild is the Microsoft Build Engine, a platform for building applications that is included with the .NET Framework and Visual Studio. It processes XML-based project files that define build tasks and targets. Attackers abuse msbuild by crafting malicious project files that contain inline C# or Visual Basic code within MSBuild task definitions. When msbuild processes these project files, it compiles and executes the embedded code in memory without writing a compiled executable to disk. This technique is particularly powerful for several reasons — msbuild is a signed Microsoft binary that is expected in development environments, the code execution happens in memory rather than through a traditional executable, and the technique can bypass application allowlisting controls that permit msbuild execution. The ability to execute arbitrary compiled .NET code through a trusted system binary with minimal disk artifacts makes msbuild abuse a favored technique for sophisticated threat actors seeking to evade endpoint detection and response tools.

---

## The Operational Problem

The detection challenges associated with these three binaries reflect and amplify the broader challenges of LOLBin detection. Each binary has a substantial legitimate use case that creates meaningful noise in most enterprise environments.

Msiexec is invoked constantly by software deployment and patch management systems. Filtering out the enormous volume of legitimate software installation activity to identify malicious msiexec invocations requires understanding what software deployment looks like in the environment and specifically what characteristics distinguish malicious use — particularly the use of remote URLs and the absence of legitimate deployment tool parent processes.

Wmic presents perhaps the most significant detection challenge of the three. Its remote execution capabilities mean that malicious activity may be initiated from a different system entirely, and the WMI event subscription persistence mechanism operates at the infrastructure level in ways that are not easily visible through standard process creation telemetry. Detecting wmic abuse requires both process creation visibility and, for persistence mechanisms, dedicated WMI event subscription monitoring.

Msbuild detection is more tractable than the other two in some respects because legitimate msbuild invocations in production environments are relatively well-defined — they typically occur on developer workstations and build servers, invoked by development tools and CI/CD pipelines. Msbuild execution on general purpose endpoints or servers outside of these contexts is inherently suspicious.

---

## Detection Opportunities

The following represents a sampling of practical starting points for hunting and detecting abuse of these utilities — this is not an exhaustive list.

**Monitor for msiexec executing remote packages**

Msiexec invocations where the `/i` flag is followed by a URL rather than a local file path are strong indicators of malicious remote package execution. Legitimate software deployment via msiexec typically references local file paths or UNC paths to internal network shares rather than external web URLs. Any msiexec invocation referencing an external URL should be treated as suspicious.

**Detect msiexec spawned by unexpected parent processes**

Msiexec invocations spawned by Office applications, scripting engines, or browser processes rather than legitimate software deployment tools warrant investigation. The parent process relationship is one of the most reliable indicators for distinguishing malicious from legitimate msiexec usage.

**Hunt for wmic remote process execution**

Wmic invocations containing the `process call create` method alongside target system specifications or command references are strong indicators of lateral movement or remote code execution activity. This capability is rarely used in legitimate administrative scenarios outside of specific management frameworks.

**Monitor for wmic spawning child processes**

Wmic is frequently used as an execution proxy where it spawns other processes including scripting engines, PowerShell, or other LOLBins. Monitoring for processes spawned as children of wmic can surface execution chains that use wmic as an intermediary to obscure the origin of malicious activity.

**Detect msbuild executing project files from suspicious locations**

Msbuild invocations referencing project files in temporary directories, user-writable locations, or remote locations including external URLs or UNC paths rather than standard development project directories are strong indicators of malicious inline code execution. Msbuild execution outside of developer workstations and build servers is inherently suspicious in most enterprise environments.

---

## MITRE ATT&CK Mapping

- **T1218.007** — System Binary Proxy Execution: Msiexec
- **T1047** — Windows Management Instrumentation
- **T1127.001** — Trusted Developer Utilities Proxy Execution: MSBuild
- **T1021.006** — Remote Services: Windows Remote Management (adjacent to wmic lateral movement)
- **T1546.003** — Event Triggered Execution: Windows Management Instrumentation Event Subscription

---

## Sources

- https://attack.mitre.org/techniques/T1218/007/
- https://attack.mitre.org/techniques/T1047/
- https://attack.mitre.org/techniques/T1127/001/
- https://lolbas-project.github.io/lolbas/Binaries/Msiexec/
- https://lolbas-project.github.io/lolbas/Binaries/Wmic/
- https://lolbas-project.github.io/lolbas/Binaries/Msbuild/
- https://redcanary.com/threat-detection-report/techniques/
