# Threat Hunt: Living off the Land Binary Abuse

## Overview

Living off the Land Binaries are legitimate, signed Windows system executables that attackers repurpose to carry out malicious activity while blending into normal administrative operations. Because these binaries are trusted components of the operating system, their execution rarely raises immediate suspicion and they frequently bypass application allowlisting controls and traditional antivirus solutions. This hunt focuses on identifying suspicious usage patterns associated with three commonly abused Windows utilities — certutil.exe, mshta.exe, and regsvr32.exe — through analysis of process creation telemetry and command-line arguments.

---

## Hunt Hypothesis

If attackers are abusing built-in Windows binaries to execute malicious code, download payloads, or bypass security controls within the environment, evidence of that activity should appear in process creation logs and command-line argument telemetry.

Potential indicators may include:

- Certutil invoked with flags associated with file download or encoding operations
- Mshta executing content from remote URLs or unusual file paths
- Regsvr32 loading scriptlets from remote locations or non-standard paths
- Any of the three binaries spawned by unexpected parent processes such as Office applications or scripting engines

---

## Data Sources

This hunt may require visibility into the following telemetry sources:

- Windows Event Logs (Security — Event ID 4688 with command-line auditing enabled)
- Endpoint process creation logs
- Command-line argument logging
- Sysmon (Event ID 1 — recommended for richer command-line and parent process visibility)
- Network connection telemetry

---

## Hunt Technique 1: Certutil Download Cradle and Decode Activity

Certutil is a legitimate certificate management utility that includes functionality for downloading files from remote URLs and encoding or decoding file content. Attackers frequently abuse these capabilities to retrieve payloads from attacker-controlled infrastructure and decode obfuscated content delivered through other means. Legitimate certutil usage rarely involves these flags outside of specific PKI management scenarios.

Hunt for certutil process creation events where the command-line arguments contain flags associated with download or decode activity.

Flags and patterns commonly associated with malicious certutil usage include:

- `-urlcache`
- `-split`
- `-decode`
- `-encode`
- `-decodehex`
- References to external URLs or UNC paths in the command line

Pay particular attention to certutil invocations on endpoints where PKI administration would not be expected, such as general purpose workstations or servers outside of certificate management infrastructure.

Related detections that may be observed in conjunction with this activity:

- Microsoft Defender for Endpoint — Suspicious certutil activity
- Windows Defender Antivirus — Script-based attack detection

---

## Hunt Technique 2: Mshta Remote Content Execution

Mshta is the Microsoft HTML Application Host, designed to execute HTA files locally installed as part of specific applications. Attackers abuse mshta to execute scripts and payloads hosted on remote servers or delivered through phishing, taking advantage of its trusted status to bypass application allowlisting controls. Legitimate mshta usage is relatively rare in most enterprise environments outside of specific legacy applications.

Hunt for mshta process creation events where the command-line arguments reference remote URLs, UNC paths, or unusual file extensions indicating execution of non-standard content.

Patterns commonly associated with malicious mshta usage include:

- Command-line arguments containing `http://` or `https://`
- Command-line arguments referencing UNC paths such as `\\`
- Mshta spawned by Office applications, browser processes, or scripting engines
- Command-line arguments referencing files in temporary or user-writable directories

Related detections that may be observed in conjunction with this activity:

- Microsoft Defender for Endpoint — Suspicious mshta execution
- Microsoft Defender for Endpoint — Office application spawning scripting interpreter

---

## Hunt Technique 3: Regsvr32 Scriptlet Execution

Regsvr32 is a COM object registration utility that attackers abuse through a technique commonly referred to as Squiblydoo, which involves using the utility to execute remotely hosted COM scriptlets or locally staged script content. This technique can bypass application allowlisting controls because regsvr32 is a trusted signed Microsoft binary. Legitimate regsvr32 usage typically involves registering DLL files during software installation and rarely involves the flags or file types associated with scriptlet execution.

Hunt for regsvr32 process creation events where the command-line arguments indicate scriptlet-based execution activity.

Patterns commonly associated with malicious regsvr32 usage include:

- The `/s /n /i` flag combination — particularly when followed by a URL or non-DLL file path
- Command-line arguments referencing `.sct` files (COM scriptlets)
- Command-line arguments containing `http://` or `https://`
- Regsvr32 spawned by Office applications, browser processes, or scripting engines

Related detections that may be observed in conjunction with this activity:

- Microsoft Defender for Endpoint — Regsvr32 used to load potentially malicious content
- Microsoft Defender for Endpoint — Suspicious process injection

---

## Investigation Considerations

If suspicious LOLBin activity is identified, investigators should consider the following:

- What parent process spawned the binary and is that relationship expected in the environment?
- Do the command-line arguments reference external URLs, UNC paths, or non-standard file types?
- Is there evidence of outbound network connections from the process following execution?
- Was a file written to disk as a result of the activity and if so what is its content and location?
- Is there evidence of follow-on execution from files or payloads retrieved or decoded by the LOLBin?
- Does the affected endpoint have a legitimate administrative use case for the binary in question?

---

## Conclusion

Certutil, mshta, and regsvr32 are among the most consistently observed LOLBins in security incidents across all threat actor categories. Because these utilities are trusted and expected components of Windows environments, their abuse is difficult to detect without command-line argument visibility and a solid understanding of what legitimate usage looks like in the environment. By hunting for the specific flags, file types, and parent process relationships associated with malicious LOLBin usage, defenders can surface this activity early in the attack chain before attackers have had the opportunity to establish deeper persistence or move laterally.

---

## Related Research

This threat hunt builds upon the research documented in:
- [Living off the Land Binary Abuse in Enterprise Environments](../research/lolbins_research.md)
