# Threat Hunt: Living off the Land Binary Abuse — Rundll32, Wscript, Cscript, and Bitsadmin

## Overview

This hunt continues the investigation of Living off the Land Binary abuse in Windows environments, focusing on rundll32.exe, the Windows Script Host engines wscript.exe and cscript.exe, and the Background Intelligent Transfer Service utility bitsadmin.exe. Each of these utilities provides attackers with distinct capabilities for executing malicious code, downloading payloads, and maintaining persistence while operating through trusted signed Windows components that blend into normal administrative activity.

This hunt focuses on identifying suspicious usage patterns associated with these utilities through analysis of process creation telemetry, command-line arguments, and parent-child process relationships.

---

## Hunt Hypothesis

If attackers are abusing these built-in Windows utilities to execute malicious code, download payloads, or establish persistence within the environment, evidence of that activity should appear in process creation logs and command-line argument telemetry.

Potential indicators may include:

- Rundll32 loading DLLs from non-standard paths or invoking the comsvcs.dll MiniDump function
- Rundll32 executing JavaScript or COM scriptlet content
- Wscript or cscript executing scripts from temporary directories or user-writable locations
- Wscript or cscript spawned by Office applications or browser processes
- Bitsadmin invoked with job creation flags referencing external URLs
- Any of these binaries spawned by unexpected parent processes

---

## Data Sources

This hunt may require visibility into the following telemetry sources:

- Windows Event Logs (Security — Event ID 4688 with command-line auditing enabled)
- Endpoint process creation logs
- Command-line argument logging
- Sysmon (Event ID 1 — recommended for richer command-line and parent process visibility)
- Network connection telemetry

---

## Hunt Technique 1: Rundll32 Suspicious DLL Execution

Rundll32 is a legitimate utility for invoking functions exported by DLL files. Attackers abuse it to execute malicious DLLs staged in attacker-controlled locations, invoke unintended functions in legitimate system DLLs, and execute script content through COM-based mechanisms. The key discriminator is what DLL is being invoked, from where, and what function is being called.

Hunt for rundll32 process creation events where the command-line arguments reference DLL files in non-standard locations such as temporary directories, user profile paths, AppData, or network shares. Also hunt for invocations referencing unusual functions or file types not associated with normal DLL registration activity.

Related detections that may be observed in conjunction with this activity:

- Microsoft Defender for Endpoint — Suspicious rundll32 activity
- Microsoft Defender for Endpoint — Suspicious process injection

---

## Hunt Technique 2: Rundll32 LSASS Memory Dumping via Comsvcs.dll

One of the most significant and consistently observed rundll32 abuse techniques involves invoking the MiniDump function exported by the legitimate Windows DLL comsvcs.dll to dump the memory of the LSASS process. This technique provides attackers with access to credential material stored in LSASS memory and has been observed across a wide range of threat actor groups including those associated with ransomware operations. This specific technique was also documented in the BumbleBee/AdaptixC2/Akira intrusion covered in the intel hunt section of this repository.

Hunt for rundll32 process creation events where the command-line arguments reference comsvcs.dll alongside the MiniDump function name or ordinal 24. Any occurrence of this pattern should be treated as a critical alert regardless of context.

Related detections that may be observed in conjunction with this activity:

- Microsoft Defender for Endpoint — Credential dumping via comsvcs.dll
- Microsoft Defender for Endpoint — LSASS memory access attempt

---

## Hunt Technique 3: Wscript and Cscript Suspicious Script Execution

The Windows Script Host engines provide a full-featured scripting runtime capable of executing VBScript and JScript files. Attackers abuse these engines primarily through phishing campaigns that deliver malicious script files as attachments or through drive-by download scenarios. The path of the script file being executed and the process that spawned the Script Host engine are the most valuable triage indicators.

Hunt for wscript and cscript process creation events where the command-line arguments reference script files in suspicious locations including temporary directories, user profile paths, downloads folders, or recently created files. Also hunt for wscript or cscript spawned by Office applications, browser processes, or archive utilities which is a strong indicator of phishing-based initial access.

Common encoded or less frequently used script file extensions to monitor for in command-line arguments include:

- `.vbe` — encoded VBScript
- `.jse` — encoded JScript
- `.wsf` — Windows Script File
- `.wsh` — Windows Script Host settings file

Related detections that may be observed in conjunction with this activity:

- Microsoft Defender for Endpoint — Suspicious script execution
- Microsoft Defender for Endpoint — Office application spawning scripting interpreter

---

## Hunt Technique 4: Bitsadmin Payload Download and Persistence

Bitsadmin exposes the Windows Background Intelligent Transfer Service and can be abused to download payloads from attacker-controlled infrastructure using a trusted Windows service. Because BITS transfers are performed by a system service rather than a user process, this technique can evade network monitoring tools that focus on process-initiated connections. BITS jobs also persist across reboots by default, making bitsadmin abuse a viable persistence mechanism in addition to a payload delivery technique.

Hunt for bitsadmin process creation events where the command-line arguments contain flags associated with job creation and file transfer referencing external URLs or unusual destination paths.

Flags and patterns commonly associated with malicious bitsadmin usage include:

- `/transfer`
- `/create`
- `/addfile`
- References to external URLs in the command line
- References to temporary directories or user-writable paths as download destinations

Related detections that may be observed in conjunction with this activity:

- Microsoft Defender for Endpoint — Suspicious BITS job creation
- Microsoft Defender for Endpoint — Network connection by bitsadmin

---

## Investigation Considerations

If suspicious LOLBin activity is identified, investigators should consider the following:

- What parent process spawned the binary and is that relationship expected in the environment?
- Do the command-line arguments reference external URLs, non-standard DLL paths, or suspicious script file locations?
- Is there evidence of outbound network connections from the process or associated BITS service following execution?
- Was a file written to disk as a result of the activity and if so what is its content and location?
- Is there evidence of follow-on execution from files retrieved or decoded by the LOLBin?
- In the case of rundll32 comsvcs.dll activity — has LSASS been accessed and are there signs of credential theft activity following the dump?
- Does the affected endpoint have a legitimate administrative use case for the specific binary invocation observed?

---

## Conclusion

Rundll32, wscript, cscript, and bitsadmin represent a broad and versatile set of attacker capabilities that are consistently observed across virtually every category of intrusion activity. The comsvcs.dll MiniDump technique via rundll32 is particularly high priority given its direct connection to credential access and its prevalence in ransomware-affiliated intrusions. By hunting for suspicious DLL invocations, script execution from unexpected locations, anomalous parent process relationships, and bitsadmin job creation referencing external infrastructure, defenders can surface LOLBin abuse early in the attack chain before attackers have had the opportunity to establish deeper persistence or move laterally.

---


